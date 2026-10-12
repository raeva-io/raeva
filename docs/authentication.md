# Authentication

Raeva can store Basic or bearer credentials in the OS credential store:

```bash
# Prompts for the username and password on a terminal.
rv login https://repo.example/repository/releases/

# Non-interactive Basic login. Registry tokens that act as Basic passwords,
# including Raeva registry tokens, belong here rather than under bearer auth.
printf '%s\n' "$RAEVA_TOKEN" |
  rv login corp --username "$RAEVA_USER" --password-stdin

# A repository that explicitly uses HTTP Bearer authentication.
printf '%s\n' "$BEARER_TOKEN" |
  rv login https://repo.example/maven2/ --auth-type bearer --password-stdin

rv auth list
rv logout corp
```

An ID passed to `login` or `logout` must identify exactly one configured
repository or mirror. If it does not, pass the URL instead. Raeva scopes
credentials to an exact normalized endpoint: scheme, lowercase host, non-default
port, and base path with a trailing slash. Raeva elides explicit default ports
(`http:80`, `https:443`) and rejects userinfo, query strings, and fragments.
`rv login` does not make a verification request. It reports
`stored; not remotely verified`.

`rv auth list` reads an atomic index under Raeva's config directory. The index
holds only the endpoint, display ID, username, and auth type. Secrets stay in
the OS credential store, and Raeva never enumerates or prints them.

Raeva also reads credentials from project `rv.toml`, the user config, and
Maven's `~/.m2/settings.xml` (including encrypted Maven passwords). Resolution
runs after mirror substitution and selects one complete credential in this
order:

1. OS credential store entry for the exact resolved endpoint.
2. Project `rv.toml` entry matching the resolved repository or mirror ID.
3. User config entry matching that ID.
4. `settings.xml` server entry matching that ID.
5. An ID-less default entry.

A Basic entry must contain a username and a password. A bearer entry must
contain a token. An incomplete entry at a higher precedence is an error, and
Raeva never borrows fields from a lower source. A mirror request looks up the
mirror endpoint. If Raeva falls back to the origin, it performs a separate
lookup for the origin endpoint. Raeva suppresses ID-less defaults when mirror
substitution crosses origins, that is, when the scheme, host or effective port
differs.

If the OS credential store is unavailable, or an expected endpoint entry is
missing, Raeva warns once and continues with the configured sources. A corrupt
stored record is a hard error. `rv sync` never prompts on stdin.

In CI, use `settings.xml` environment interpolation rather than the OS
credential store:

```xml
<settings>
  <servers>
    <server>
      <id>corp</id>
      <username>${env.RAEVA_USER}</username>
      <password>${env.RAEVA_TOKEN}</password>
    </server>
  </servers>
</settings>
```
