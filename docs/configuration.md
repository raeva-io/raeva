# Configuration

Raeva reads dependencies only from `pom.xml`. Tool settings live in an optional
project `rv.toml` and a user `config.toml`: repositories, mirrors, credentials,
network limits, and security policy. Neither file can declare dependencies.
Maven's `~/.m2/settings.xml` is also read for mirrors and server credentials.

## Environment variables

| Variable | Effect |
| --- | --- |
| `RAEVA_HOME` | Root for Raeva's config, store, and cache directories. When unset, the platform config/data/cache directories are used. |
| `SOURCE_DATE_EPOCH` | Unix timestamp used as the SPDX creation time for reproducible output. |
| `RV_TIMEOUT` | Network timeout in seconds. Overrides `network.timeout` from `rv.toml`. For artifact downloads it bounds the wait for response headers and the idle gap between body chunks, not the total transfer time. |
| `RV_LOW_SPEED_LIMIT` | Minimum artifact download speed in bytes per second (default 1024; 0 disables). Overrides `network.low_speed_limit` from `rv.toml`. |
| `RV_LOW_SPEED_TIME` | Seconds a download may stay below `RV_LOW_SPEED_LIMIT` before rv retries it (default 30). Overrides `network.low_speed_time` from `rv.toml`. |
| `RV_MAX_ARTIFACT_SIZE` | Maximum size in bytes of a single downloaded artifact (default 17179869184, 16 GiB). rv rejects larger bodies with an error naming the artifact. |
| `RV_RETRIES` | Number of network retry attempts. Overrides `network.retries` from `rv.toml`. |

If an artifact download stays below the speed limit for the whole window,
rv retries it on a new connection, up to `RV_RETRIES` times.
Time spent writing to the local store does not count. Downloads that finish
within the window are never checked. The same settings are available in
user `config.toml` and project `rv.toml`:

```toml
[network]
low_speed_limit = 1024 # bytes per second; 0 disables
low_speed_time = 30    # seconds
```

`JAVA_VERSION` is also read as a fallback value for `${java.version}` POM interpolation, since `rv` does not run a JVM.

## Metadata checksum policy

Repositories rewrite `maven-metadata.xml` in place, and some publish stale
checksum files next to it. When the metadata does not match its checksum,
rv downloads both files again. If they disagree after retry, rv warns with
`METADATA_CHECKSUM_MISMATCH` and uses the metadata. This matches Maven's
default `warn` checksum policy.

With `<checksumPolicy>fail</checksumPolicy>` in a POM or `settings.xml`, rv
rejects mismatched metadata. In `rv.toml`, a repository entry
accepts `releases-checksum-policy = "fail"` and
`snapshots-checksum-policy = "fail"`. Artifact and POM checksum mismatches
always fail, and `rv.lock` pins timestamped snapshot versions and
artifact and POM hashes.
