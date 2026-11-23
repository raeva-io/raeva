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

A registry that ignores the username still needs a non-empty one, such as
`token`: raeva refuses an empty one.

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

Either one adds to Maven Central. Maven does not read `raeva.toml`: a
repository declared only there is available to raeva alone. Declare it in
`pom.xml` or a `settings.xml` profile when `mvn` must use it. A `<server>`
whose id no declared repository or mirror has is never used.

Hints name `<ID>_USER` and `<ID>_TOKEN`: the repository id in upper case,
with every character other than a letter or digit turned into `_`, and
`REPO_` in front when it does not start with a letter.
`corp-releases` reads `CORP_RELEASES_USER` and `CORP_RELEASES_TOKEN`. An
unset variable stays as written. The repository refuses that literal text.
`raeva sync` and `raeva doctor` name the variable.

A `<server>` can hold a bearer token as Maven reads it: a
`<configuration><httpHeaders><property>` named `Authorization` with the
value `Bearer <token>`. Passwords encrypted with `mvn --encrypt-password`
are decrypted with the master password in `~/.m2/settings-security.xml`,
or in the file a command-line `-Dsettings.security` names, as in Maven. A
security file raeva cannot read decrypts nothing, as in Maven. A
password that cannot be decrypted is dropped with `CREDENTIAL_DROPPED`. A
`<server>` with a username whose password is dropped gives no credential
for its id, and an `[[auth]]` entry without an id does not answer in its
place, so unless a `raeva.toml` or `config.toml` entry has the id, a
repository that allows anonymous reads still serves the sync, as for
Maven. A bearer token on that `<server>` is still sent. A `<server>` left
with no credential fields is skipped, as below. A proxy whose password is
dropped gets no credentials.

A credential in the URL (`https://user:pass@host/`) is refused (exit 3).
`raeva.lock` would record it. Keep secrets out of a committed `raeva.toml`.
`raeva` never prompts for credentials.

## Precedence

After mirror substitution, Raeva takes one complete credential from the
first source that has one:

1. The project `raeva.toml` entry with the id of the repository or mirror.
2. The user `config.toml` entry with that id.
3. The `settings.xml` `<server>` with that id: the first, as in Maven, when
   several have it, even when it carries no credential. In the Maven 3.10
   mode a server also has each id its `<aliases>` list, in its place in the
   file. Maven likewise keeps the first mirror and the first active proxy
   of an id, a proxy without an `<id>` having `default`.
4. An `[[auth]]` entry without an id, from `raeva.toml`, then `config.toml`.

A Basic entry needs a username and a password, a bearer entry a token. A
partly filled entry is an error, except a `<server>` with a username
whose password was dropped (above); fields are never combined across
sources.
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

In the Maven 3.10 mode the username and password of a `settings.xml`
`<server>` go where Maven 3.10 sends them. Its
`maven.repository.credentialScope` (from `-D`, `.mvn/maven.config`,
`.mvn/jvm.config` or a `settings.xml` profile Maven's session reads) binds
the server's id to origins: those of the `settings.xml` mirrors with the
id, of the repositories and plugin repositories with the id of the profiles
`<activeProfiles>` names, of Maven Central for `central` unless their
repositories and their plugin repositories both have one with that id, and
of the server's `<repositoryOrigins>`. raeva also
binds the id to the `config.toml` repositories and mirrors with it, but not
to `raeva.toml`'s or the POMs'. With `origin`, the default, the credential
goes only to a bound origin when the id has one, and anywhere, as above,
when it has none; `strict` sends it only to a bound origin; `id` binds
nothing. Elsewhere it is withheld with `ID_CREDENTIAL_WITHHELD`. A
`<repositoryOrigin>` Maven refuses, another value of the property (exit 2
as a command-line `-D`), or, unless the scope is `id`, a mirror or
repository URL whose origin raeva cannot read as Maven does, such as a
non-ASCII host, is refused (exit 3). Maven also sends no username and password to a
repository a dependency's POM declares that no mirror replaces, unless
`aether.remoteRepositoryManager.authToDescriptorRepositories=true`, while
it collects the dependencies below that POM, but does when it fetches that
POM's own parent or imported BOMs through it, unless the repository came
in above that POM the same way. raeva does the same, and warns
`ID_CREDENTIAL_WITHHELD` where it withholds them. Mirror the repository or
set the property to send them. A bearer token from
`<httpHeaders>` and an `[[auth]]` entry are not bound, as Maven sends such
headers by id. The Maven 3.9 mode sends by id, as Maven 3.9 does.

An entry without an id goes only to an origin your own files name: a
repository or mirror in `config.toml` or an active `settings.xml` profile,
except in a settings file `.mvn/maven.config` names with `-s`, or a built-in repository when none is configured (Maven Central at the
URL a `-D` or `MAVEN_REPO_CENTRAL` gives in the Maven 3.10 mode, not one
from `.mvn/`). Elsewhere, including
repositories only the project's POMs or `raeva.toml` declare and mirrors on
another host, it is withheld with `DEFAULT_CREDENTIAL_WITHHELD` or
`CROSS_HOST_MIRROR`. Give such a repository an id and an entry with that id.

## Checking credentials

`raeva doctor` asks each configured repository, each repository the
project's POMs declare, and with `[plugins] lock = true` each plugin
repository of the POMs and of settings.xml, for metadata with the credentials `raeva sync` would send. It reports
connectivity, TLS and authentication failures, whether credentials were
sent, and whether the store is writable. A POM repository sync ignores, such
as plain HTTP to another host, is listed without a request, as is a
repository whose URL raeva cannot read, which sync skips as Maven does, with
a `warn`; a default that every module replaces under its id is not asked,
and a `file:` repository without its directory fails. A 401 or 403, here
and in a failed `raeva sync`, says when the Maven 3.10 credential scope
withheld a `settings.xml` username and password.

A check is `ok`, `fail`, `warn`, `info`, or `inconclusive`. A `warn` does
not change the exit status. Inconclusive is not a pass. A repository that answers 404 for the file `raeva doctor` asks for is
inconclusive, and some private repositories answer 404 to a wrong
credential too. Its row says whether credentials were sent. `raeva doctor`
exits 0 when no check fails, with a note that counts the inconclusive
checks, so check such a repository by fetching a file you know it holds,
such as one you published: a `raeva sync` that the store already answers
sends no request. Through a mirror of `central` or `*`, the row adds that a
private registry that does not proxy Maven Central belongs next to Central
as a repository, not as its mirror.
