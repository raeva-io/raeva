# Authentication

Raeva reads repository credentials from `<server>` entries in Maven's
`~/.m2/settings.xml` and from `[[auth]]` in the project `raeva.toml` and
the user `config.toml`. In CI, interpolate `settings.xml`:

```xml
<settings>
  <servers>
    <server>
      <id>raeva</id>
      <username>${env.RAEVA_USER}</username>
      <password>${env.RAEVA_TOKEN}</password>
    </server>
  </servers>
</settings>
```

The `<server>` id must match the id of the repository the credential is
for. Declare that repository in the project's `pom.xml`:

```xml
<repositories>
  <repository>
    <id>raeva</id>
    <url>https://repo.example/maven/</url>
  </repository>
</repositories>
```

or in `raeva.toml`:

```toml
[[repositories]]
id = "raeva"
url = "https://repo.example/maven/"
```

Either one adds to Maven Central. A `<server>` whose id no declared
repository or mirror has is never used.

Hints name `<ID>_USER` and `<ID>_TOKEN`: the repository id in upper case,
with every character other than a letter or digit turned into `_`, and
`REPO_` in front when it does not start with a letter.
`corp-releases` reads `CORP_RELEASES_USER` and `CORP_RELEASES_TOKEN`. An
unset variable stays as written. The repository refuses that literal text.
`raeva sync` and `raeva doctor` name the variable.

A `<server>` can hold a bearer token as Maven reads it: a
`<configuration><httpHeaders><property>` named `Authorization` with the
value `Bearer <token>`. Passwords encrypted with `mvn --encrypt-password`
are decrypted with the master password in `~/.m2/settings-security.xml`. A
password that cannot be decrypted is dropped with `CREDENTIAL_DROPPED`.

A credential in the URL (`https://user:pass@host/`) is refused (exit 3).
`raeva.lock` would record it. Keep secrets out of a committed `raeva.toml`.
`raeva` never prompts for credentials.

## Precedence

After mirror substitution, Raeva takes one complete credential from the
first source that has one:

1. The project `raeva.toml` entry with the id of the repository or mirror.
2. The user `config.toml` entry with that id.
3. The `settings.xml` `<server>` with that id.
4. An `[[auth]]` entry without an id, from `raeva.toml`, then `config.toml`.

A Basic entry needs a username and a password, a bearer entry a token. A
partly filled entry is an error; fields are never combined across sources.
An entry with an id but no credential fields, such as a `<server>` with
only deploy settings, is skipped.

A request through a mirror uses the mirror's id and endpoint. A mirror
without an id takes the repository's id when both have the same scheme,
host and port.

An entry with an id goes to any repository with that id that your
configuration or the project's own POMs declare, as in Maven, wherever it
points. Review the repositories of a project you cloned before you sync it
with credentials. A pull request can change the project's POMs, so give a
job that syncs one no credentials, or a mirror with `<mirrorOf>*</mirrorOf>`
so that every repository goes through it. A repository that a fetched POM (a remote parent, a
dependency or an imported BOM) declares with the id gets the entry only
when its origin (scheme, host and port) is one that a configured
repository, mirror or `transitive_repository_allowlist` entry, or a
repository of the project's own POMs, already uses. Elsewhere it is withheld
with `ID_CREDENTIAL_WITHHELD`; declare the repository in your configuration
if it should get the credential.

An entry without an id goes only to an origin your own files name: a
repository or mirror in `config.toml` or an active `settings.xml` profile,
or a built-in repository when none is configured. Elsewhere, including
repositories only the project's POMs or `raeva.toml` declare and mirrors on
another host, it is withheld with `DEFAULT_CREDENTIAL_WITHHELD` or
`CROSS_HOST_MIRROR`. Give such a repository an id and an entry with that id.

## Checking credentials

`raeva doctor` asks each configured repository, and each repository the
project's POMs declare, for metadata with the credentials `raeva sync` would send. It reports
connectivity, TLS and authentication failures, whether credentials were
sent, and whether the store is writable. A POM repository sync ignores, such
as plain HTTP to another host, is listed without a request, a default that
every module replaces under its id is not asked, and a `file:` repository
without its directory fails.

A check is `ok`, `fail`, `info`, or `inconclusive`. Inconclusive is not a
pass. A repository that answers 404 for the file `raeva doctor` asks for is
inconclusive, and some private repositories answer 404 to a wrong
credential too. Its row says whether credentials were sent. `raeva doctor`
exits 0 when no check fails, with a note that counts the inconclusive
checks, so check such a repository with `raeva sync` and a dependency that
lives there.
