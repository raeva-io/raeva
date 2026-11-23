"""Check the cases in cases.txt against real Maven 3.9 and 3.10 distributions.

Each case is a dependency graph. The script writes its POMs, empty jars and
version metadata into a scratch file:// repository, runs
`mvn dependency:list` on the root with each distribution, and compares the
resolved set with the case's `expect 3.9:` and `expect 3.10:` lines. The
Rust tests in rv-resolver/src/solver/tests/modes.rs solve the same cases
in each mode and compare with the same lines.

Run from the repository root, with a JDK installed:

    python3 -I test-fixtures/maven-modes/differential.py <scratch-directory> \\
        --maven 3.9=<apache-maven-3.9.x>/bin/mvn \\
        --maven 3.10=<apache-maven-3.10.x>/bin/mvn \\
        [--maven 3.9-bf=<a 3.9.x mvn wrapper adding
                        -Daether.dependencyCollector.impl=bf>] \\
        [--maven 3.10-df=<a 3.10.x mvn wrapper adding
                         -Daether.dependencyCollector.impl=df>] \\
        [--tail <local repository holding maven-dependency-plugin>] \\
        [--settings <settings.xml for plugin downloads>] [--case <name>] \\
        [--cases <case file, cases.txt by default>]

The plugin is resolved from Maven Central, or from the repository named by
--tail (read only, as maven.repo.local.tail). Each case's own artifacts go
to a fresh local repository under the scratch directory.

Case syntax, one item per line (`#` starts a comment):

    ## name
    root: <dependencies>
    manage: <managed dependencies of the root>
    <project> > <dependencies> | <managed dependencies>
    <project> => [group:]artifact:version     (a relocation; `_` leaves a
                                              field out)
    versions [group:]artifact v1 v2 ...       (listed versions)
    expect 3.9: <resolved set>
    expect 3.10: <resolved set>      (or "ERR <text>" for a failure)
    expect 3.9-bf: <resolved set>    (Maven 3.9 with the breadth-first
                                     collector, where it differs from 3.10)
    expect 3.10-df: <resolved set>   (Maven 3.10 with the depth-first
                                     collector, where it differs from 3.9)
    raeva 3.9: <resolved set>        (what raeva's 3.9 mode resolves where it
                                     knowingly differs; this script skips it)

A coordinate is `[group:]artifact:version`, group `g` when left out, and a
dependency may add `@scope`, `?` (optional), `!artifact` or
`!group:artifact` (an exclusion) and `=path` (a system path, written as
`${java.home}/lib/jrt-fs.jar` so the file exists). The resolved set lists
`[group:]artifact:version[@scope]`, sorted, `@compile` left out.
"""

import argparse
import hashlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
G = "g"


def parse_cases(text):
    cases = {}
    current = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip() if not raw.startswith("##") else raw.strip()
        if not line:
            continue
        if line.startswith("## "):
            current = {"projects": [], "versions": {}, "root": "", "manage": "", "expect": {}}
            cases[line[3:].strip()] = current
        elif line.startswith("root:"):
            current["root"] = line[5:].strip()
        elif line.startswith("manage:"):
            current["manage"] = line[7:].strip()
        elif line.startswith("raeva 3.9:"):
            continue
        elif line.startswith("expect "):
            mode, value = line[7:].split(":", 1)
            current["expect"][mode.strip()] = value.strip()
        elif line.startswith("versions "):
            words = line.split()[1:]
            current["versions"][ga(words[0])] = words[1:]
        else:
            current["projects"].append(line)
    return cases


def ga(text):
    parts = text.split(":")
    return (G, parts[0]) if len(parts) == 1 else (parts[0], parts[1])


def gav(text):
    parts = text.split(":")
    if len(parts) == 2:
        return G, parts[0], parts[1]
    return parts[0], parts[1], parts[2]


MARKERS = "@?!="


def parse_dep(token):
    cut = min([token.index(m) for m in MARKERS if m in token] or [len(token)])
    group, artifact, version = gav(token[:cut])
    dep = {"g": group, "a": artifact, "v": version, "scope": None, "optional": False, "excl": [], "path": None}
    rest = token[cut:]
    while rest:
        marker = rest[0]
        end = min([i for i, ch in enumerate(rest) if ch in MARKERS and i > 0] or [len(rest)])
        value = rest[1:end]
        if marker == "@":
            dep["scope"] = value
        elif marker == "?":
            dep["optional"] = True
        elif marker == "=":
            dep["path"] = "${java.home}/lib/jrt-fs.jar"
        else:
            dep["excl"].append(ga(value))
        rest = rest[end:]
    return dep


def dep_xml(dep):
    xml = f"<dependency><groupId>{dep['g']}</groupId><artifactId>{dep['a']}</artifactId>"
    if dep["v"] != "_":
        xml += f"<version>{dep['v']}</version>"
    if dep["scope"]:
        xml += f"<scope>{dep['scope']}</scope>"
    if dep["optional"]:
        xml += "<optional>true</optional>"
    if dep["path"]:
        xml += f"<systemPath>{dep['path']}</systemPath>"
    if dep["excl"]:
        xml += "<exclusions>" + "".join(
            f"<exclusion><groupId>{g}</groupId><artifactId>{a}</artifactId></exclusion>"
            for g, a in dep["excl"]
        ) + "</exclusions>"
    return xml + "</dependency>"


def deps_xml(text, tag="dependencies"):
    deps = [parse_dep(t) for t in text.split()]
    if not deps:
        return ""
    body = "".join(dep_xml(d) for d in deps)
    if tag == "dependencyManagement":
        return f"<dependencyManagement><dependencies>{body}</dependencies></dependencyManagement>"
    return f"<dependencies>{body}</dependencies>"


def project_xml(group, artifact, version, body):
    return (
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>'
        f"<groupId>{group}</groupId><artifactId>{artifact}</artifactId>"
        f"<version>{version}</version>{body}</project>\n"
    )


def write_with_sums(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.with_name(path.name + ".sha1").write_text(hashlib.sha1(data).hexdigest())


def empty_jar():
    from io import BytesIO

    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as jar:
        info = zipfile.ZipInfo("META-INF/MANIFEST.MF", (2020, 1, 1, 0, 0, 0))
        jar.writestr(info, "Manifest-Version: 1.0\n")
    return buffer.getvalue()


def build_repository(case, repo):
    listed = {}
    jar = empty_jar()
    for line in case["projects"]:
        relocation = None
        head = line
        if "=>" in line:
            head, target = line.split("=>", 1)
            relocation = gav(target.strip())
        head, managed = head.split("|", 1) if "|" in head else (head, "")
        head, deps = head.split(">", 1) if ">" in head else (head, "")
        group, artifact, version = gav(head.strip())
        body = deps_xml(deps) + deps_xml(managed, "dependencyManagement")
        if relocation:
            fields = zip(("groupId", "artifactId", "version"), relocation)
            body += (
                "<distributionManagement><relocation>"
                + "".join(f"<{tag}>{value}</{tag}>" for tag, value in fields if value != "_")
                + "</relocation></distributionManagement>"
            )
        base = repo.joinpath(*group.split("."), artifact, version)
        write_with_sums(base / f"{artifact}-{version}.pom", project_xml(group, artifact, version, body).encode())
        write_with_sums(base / f"{artifact}-{version}.jar", jar)
        listed.setdefault((group, artifact), []).append(version)
    for key, versions in {**listed, **case["versions"]}.items():
        group, artifact = key
        items = "".join(f"<version>{v}</version>" for v in versions)
        metadata = (
            f"<metadata><groupId>{group}</groupId><artifactId>{artifact}</artifactId>"
            f"<versioning><versions>{items}</versions></versioning></metadata>\n"
        )
        write_with_sums(repo.joinpath(*group.split("."), artifact, "maven-metadata.xml"), metadata.encode())


def root_pom(case, repo):
    body = deps_xml(case["root"]) + deps_xml(case["manage"], "dependencyManagement")
    body += (
        "<repositories><repository><id>fixture</id>"
        f"<url>{repo.as_uri()}</url>"
        "<releases><checksumPolicy>ignore</checksumPolicy></releases>"
        "</repository></repositories>"
    )
    return project_xml("root", "root", "1", body)


def label(line):
    # group:artifact:type:version:scope, perhaps followed by " -- module ...".
    parts = line.split(" ")[0].split(":")
    if len(parts) == 6:
        group, artifact, _type, _classifier, version, scope = parts
    else:
        group, artifact, _type, version, scope = parts[:5]
    text = f"{artifact}:{version}" if group == G else f"{group}:{artifact}:{version}"
    return text if scope == "compile" else f"{text}@{scope}"


def run_maven(mvn, workdir, args):
    out = workdir / "list.txt"
    out.unlink(missing_ok=True)
    command = [
        mvn, "-B", "-ntp",
        f"-Dmaven.repo.local={workdir / 'm2'}",
        "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:list",
        f"-DoutputFile={out}",
        "-DexcludeTransitive=false",
    ]
    if args.tail:
        command.append(f"-Dmaven.repo.local.tail={args.tail}")
    if args.settings:
        command += ["-s", str(args.settings)]
    log = subprocess.run(command, cwd=workdir, capture_output=True, text=True)
    (workdir / "mvn.log").write_text(log.stdout + log.stderr)
    if log.returncode != 0:
        errors = [l for l in log.stdout.splitlines() if l.startswith("[ERROR]")]
        return "ERR " + (errors[0][8:] if errors else "exit %d" % log.returncode)
    lines = [l.strip() for l in out.read_text().splitlines()]
    found = [label(l) for l in lines if l and not l.startswith("The following") and l != "none"]
    return " ".join(sorted(found))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--maven", action="append", required=True, help="MODE=path/to/mvn")
    parser.add_argument("--tail", type=Path)
    parser.add_argument("--settings", type=Path)
    parser.add_argument("--case")
    parser.add_argument("--cases", type=Path, default=HERE / "cases.txt", help="the case file")
    args = parser.parse_args()
    mavens = dict(item.split("=", 1) for item in args.maven)
    cases = parse_cases(args.cases.read_text())
    base = args.scratch.resolve()
    failures = 0
    for name, case in cases.items():
        if args.case and name != args.case:
            continue
        work = base / name
        if work.exists():
            shutil.rmtree(work)
        repo = work / "repository"
        build_repository(case, repo)
        for mode, mvn in mavens.items():
            run_dir = work / f"maven-{mode}"
            run_dir.mkdir(parents=True)
            (run_dir / "pom.xml").write_text(root_pom(case, repo))
            got = run_maven(mvn, run_dir, args)
            want = case["expect"].get(mode)
            if mode == "3.9-bf" and want is None:
                want = case["expect"].get("3.10")
            if mode == "3.10-df" and want is None:
                want = case["expect"].get("3.9")
            ok = want is not None and (got == want or (want.startswith("ERR") and got.startswith("ERR")))
            failures += not ok
            print(f"{'ok  ' if ok else 'FAIL'} {name} [{mode}] {got}" + ("" if ok else f"\n     expected {want}"))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
