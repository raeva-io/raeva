"""Construct local Maven fixtures and assert their verbose dependency trees.

The script creates minimal POMs, empty jars, and metadata in a scratch file://
repository. Plugin downloads and Maven output also stay in scratch. The Rust
tests in rv-resolver/src/solver/tests/nearest.rs use fetch concurrency 1, 2, and 32.

With Maven and JDK 21 installed, run from the repository root:

    python3 -I test-fixtures/nearest-backtracking/reproduce.py <scratch-directory>

Each verbose tree is in maven/<case>/mvn.log under the scratch directory.
Pass --settings <settings.xml> to use a mirror for plugin downloads.
Pass --case <name> to run one scenario.

Scenarios use soft versions unless brackets mark a hard constraint:

- backtrack: a:1, b -> a:2, c -> a:[2,4), with versions 1, 2, 3.
  Maven selects a:2 and its child, removing a:1's child.
- backtrack-reversed: a:1, c -> a:[2,4), b -> a:2. Maven selects a:3.
- backtrack-prune: backtrack followed by d -> a:[3,4). Maven selects a:3.
- range-alternatives: b -> a:[1,2],[4], c -> a:[2,3], with versions 1 through 4.
  Maven selects a:2; neither range's maximum satisfies both ranges.
- hard-acceptability: b -> a:[2,3), c -> a:1. Maven selects a:2.
- hard-conflict: a:[1], b -> a:[2,3). Maven reports a version conflict (exit 1).
- relocation: new:2, p -> old:[1], with old:1 -> new:1.
  Maven selects new:2 and its child.
- relocation-version: new:2, p -> new:[1], with new:1 -> new:3.
  Maven selects new:2.
- relocation-target-range: new:2, p -> old:[1], with old:1 -> new:1 and the
  target managed as [1]. Maven selects new:1, retaining the target constraint.
- relocation-siblings: old:[1], new:2, with old:1 -> new:1. Maven selects new:2.

Maven's NearestVersionSelector retains acceptable candidates, backtracks when a
hard constraint rejects the winner, and prefers higher sibling versions:
https://raw.githubusercontent.com/apache/maven-resolver/maven-resolver-1.9.22/maven-resolver-util/src/main/java/org/eclipse/aether/util/graph/transformer/NearestVersionSelector.java

DfDependencyCollector enumerates range versions and restarts collection with a
relocation target's own version:
https://raw.githubusercontent.com/apache/maven-resolver/maven-resolver-1.9.22/maven-resolver-impl/src/main/java/org/eclipse/aether/internal/impl/collect/df/DfDependencyCollector.java
"""

import argparse
import os
from pathlib import Path
import subprocess
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("scratch", type=Path)
parser.add_argument("--settings", type=Path)
parser.add_argument("--case", help="Run just one named scenario")
args = parser.parse_args()
base = args.scratch.resolve()
base.mkdir(parents=True, exist_ok=True)
repo = base / "repository"

cases = {'relocation-target-range': {'root': [('new', '2'), ('p', '1')],
                             'deps': {'p:1': [('old', '[1]')]},
                             'relocations': {'old:1': ('new', '1')},
                             'managed': [('new', '[1]')]},
 'range-alternatives': {'root': [('b', '1'), ('c', '1')],
                        'deps': {'b:1': [('a', '[1,2],[4]')], 'c:1': [('a', '[2,3]')]},
                        'versions': {'a': ['1', '2', '3', '4']}},
 'backtrack': {'root': [('a', '1'), ('b', '1'), ('c', '1')],
               'deps': {'b:1': [('a', '2')],
                        'c:1': [('a', '[2,4)')],
                        'a:1': [('old-child', '1')],
                        'a:2': [('winner-child', '1')]},
               'versions': {'a': ['1', '2', '3']}},
 'backtrack-reversed': {'root': [('a', '1'), ('c', '1'), ('b', '1')],
                        'deps': {'b:1': [('a', '2')], 'c:1': [('a', '[2,4)')]},
                        'versions': {'a': ['1', '2', '3']}},
 'backtrack-prune': {'root': [('a', '1'), ('b', '1'), ('c', '1'), ('d', '1')],
                     'deps': {'b:1': [('a', '2')],
                              'c:1': [('a', '[2,4)')],
                              'd:1': [('a', '[3,4)')]},
                     'versions': {'a': ['1', '2', '3']}},
 'hard-acceptability': {'root': [('b', '1'), ('c', '1')],
                        'deps': {'b:1': [('a', '[2,3)')], 'c:1': [('a', '1')]},
                        'versions': {'a': ['1', '2']}},
 'hard-conflict': {'root': [('a', '[1]'), ('b', '1')],
                   'deps': {'b:1': [('a', '[2,3)')]},
                   'versions': {'a': ['1', '2']}},
 'relocation': {'root': [('new', '2'), ('p', '1')],
                'deps': {'p:1': [('old', '[1]')],
                         'new:2': [('winner-child', '1')],
                         'new:1': [('old-child', '1')]},
                'relocations': {'old:1': ('new', '1')}},
 'relocation-version': {'root': [('new', '2'), ('p', '1')],
                        'deps': {'p:1': [('new', '[1]')]},
                        'relocations': {'new:1': ('new', '3')}},
 'relocation-siblings': {'root': [('old', '[1]'), ('new', '2')],
                         'relocations': {'old:1': ('new', '1')}}}

expected = {
    "backtrack": "2",
    "backtrack-reversed": "3",
    "backtrack-prune": "3",
    "range-alternatives": "2",
    "hard-acceptability": "2",
    "hard-conflict": None,
    "relocation": "2",
    "relocation-version": "2",
    "relocation-siblings": "2",
    "relocation-target-range": "1",
}


def dependency_xml(group, dependencies):
    return "<dependencies>" + "".join(
        f"<dependency><groupId>{group}</groupId>"
        f"<artifactId>{artifact}</artifactId><version>{version}</version></dependency>"
        for artifact, version in dependencies
    ) + "</dependencies>"


def project_xml(group, artifact, version, body):
    return (
        "<project><modelVersion>4.0.0</modelVersion>"
        f"<groupId>{group}</groupId><artifactId>{artifact}</artifactId>"
        f"<version>{version}</version>{body}</project>"
    )


if args.case and args.case not in cases:
    parser.error(f"Unknown case: {args.case}")

for name, case in cases.items():
    if args.case and name != args.case:
        continue
    group = "test." + name
    dependencies = case.get("deps", {})
    relocations = case.get("relocations", {})
    artifacts = {tuple(key.split(":")) for key in dependencies.keys() | relocations.keys()}
    artifacts |= {(a, v) for a, vs in case.get("versions", {}).items() for v in vs}
    artifacts |= set(relocations.values())
    artifacts |= {
        (a, v) for deps in [case["root"], *dependencies.values()]
        for a, v in deps if not v.startswith(("(", "["))
    }
    for artifact, version in sorted(artifacts):
        path = repo / group.replace(".", "/") / artifact / version
        path.mkdir(parents=True, exist_ok=True)
        key = f"{artifact}:{version}"
        body = dependency_xml(group, dependencies.get(key, []))
        if key in relocations:
            target_artifact, target_version = relocations[key]
            body += (
                "<distributionManagement><relocation>"
                f"<artifactId>{target_artifact}</artifactId><version>{target_version}</version>"
                "</relocation></distributionManagement>"
            )
        (path / f"{artifact}-{version}.pom").write_text(
            project_xml(group, artifact, version, body)
        )
        with zipfile.ZipFile(path / f"{artifact}-{version}.jar", "w"):
            pass

    for artifact in sorted({a for a, _ in artifacts}):
        versions = sorted(v for a, v in artifacts if a == artifact)
        metadata = (
            f"<metadata><groupId>{group}</groupId><artifactId>{artifact}</artifactId>"
            "<versioning><versions>"
            + "".join(f"<version>{v}</version>" for v in versions)
            + "</versions><lastUpdated>20261011000000</lastUpdated></versioning></metadata>"
        )
        (repo / group.replace(".", "/") / artifact / "maven-metadata.xml").write_text(metadata)

    project = base / "maven" / name
    project.mkdir(parents=True, exist_ok=True)
    body = (
        "<repositories><repository><id>fixture</id>"
        f"<url>{repo.as_uri()}</url><releases><checksumPolicy>ignore</checksumPolicy>"
        "</releases></repository></repositories>"
        + dependency_xml(group, case["root"])
        + "<dependencyManagement>" + dependency_xml(group, case.get("managed", []))
        + "</dependencyManagement>"
    )
    (project / "pom.xml").write_text(project_xml(group, "root", "1", body))
    env = dict(os.environ, JAVA_HOME="/usr/lib/jvm/java-21-openjdk")
    env.setdefault("MAVEN_OPTS", "-Xmx512m -XX:ActiveProcessorCount=6")
    command = ["mvn", "-B", "-ntp"]
    if args.settings:
        command += ["-s", str(args.settings.resolve())]
    command += [f"-Dmaven.repo.local={base}/m2", "dependency:tree", "-Dverbose"]
    with (project / "mvn.log").open("w") as log:
        run = subprocess.run(command, cwd=project, env=env, stdout=log, stderr=subprocess.STDOUT)
    output = (project / "mvn.log").read_text()
    version = expected[name]
    if version is None:
        assert run.returncode == 1 and "Could not resolve version conflict" in output, output
    else:
        artifact = "new" if name.startswith("relocation") else "a"
        selected = f"{group}:{artifact}:jar:{version}:compile"
        assert run.returncode == 0 and any(
            selected in line and "omitted" not in line for line in output.splitlines()
        ), output
    print(f"{name}: verified (exit {run.returncode})", flush=True)
