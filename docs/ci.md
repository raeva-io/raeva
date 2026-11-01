# Checking the lock in CI

On GitHub Actions, use [setup-raeva](https://github.com/raeva-io/setup-raeva).
It installs a pinned raeva, caches the store, and runs `raeva sync --frozen`.
Its `examples/gitlab-ci.yml` and `examples/Jenkinsfile` show the same check
on GitLab CI and Jenkins. This page lists what any other CI job needs.

## Install a pinned release

Pin the raeva version: a lock written by a newer raeva can use a schema
that an older one refuses. Pin the archive's SHA-256 too, taken once from the
release's `sha256.sum`, so a replaced release asset fails the job:

```sh
RAEVA_VERSION=<the version your developers use>
RAEVA_ARCHIVE=raeva-x86_64-unknown-linux-gnu.tar.gz
RAEVA_SHA256=<the SHA-256 that sha256.sum gives for $RAEVA_ARCHIVE>
curl --proto '=https' --tlsv1.2 -fsSL -o raeva.tar.gz \
  "https://github.com/raeva-io/raeva/releases/download/v$RAEVA_VERSION/$RAEVA_ARCHIVE"
echo "$RAEVA_SHA256  raeva.tar.gz" | sha256sum -c -
mkdir -p "$HOME/.local/bin"
tar -xzf raeva.tar.gz -C "$HOME/.local/bin" --strip-components=1 --wildcards '*/raeva'
```

On Alpine or another musl image, take the `x86_64-unknown-linux-musl` or
`aarch64-unknown-linux-musl` archive ([Installation](installation.md)).

## Lock every platform CI runs on

`raeva sync` locks the platform it runs on. When developers write the lock on
a Mac and CI runs Linux, lock both:

```sh
raeva sync --platforms linux-x86_64,macos-aarch64
```

Later syncs keep the platforms the lock records. The names are
`linux-x86_64`, `linux-aarch64`, `macos-x86_64`, `macos-aarch64`,
`windows-x86_64`, and `windows-aarch64`.

## Name the JDK

POM profiles can activate by JDK version, so raeva needs the JDK the build
uses. Set `JAVA_HOME` in the job. When CI builds on several JDKs, list them
in `raeva.toml` and run `raeva sync`; `--frozen` then passes on each:

```toml
[lock]
jdks = ["17", "21"]
```

See [The JDK version](configuration.md#the-jdk-version).

## Cache the store

Downloads go to the store under `RAEVA_HOME`. To cache it between jobs, set
`RAEVA_HOME` to a directory the CI system caches, and cache
`$RAEVA_HOME/store` and `$RAEVA_HOME/metadata.db` keyed on `raeva.lock`.
A job with a warm store downloads no artifact the store already holds.

## Merge the lock

Tell git not to merge `raeva.lock` line by line:

```sh
printf 'raeva.lock -merge linguist-generated=true\n' >> .gitattributes
```

With `-merge`, git keeps your side of a conflicted lock without conflict
markers and still reports the conflict. Run `raeva sync` and add the lock.
