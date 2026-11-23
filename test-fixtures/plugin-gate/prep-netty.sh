#!/usr/bin/env bash
# netty's codec-native-quic clones BoringSSL and quiche and fetches quiche's
# crates while it builds, outside Maven. Fetch them at the commits its POM
# pins before the network goes; the build then finds them and skips the
# clones, and cargo reads the crates from $CARGO_HOME.
#
#   prep-netty.sh <checkout>
set -eu
src=$1
pom=$src/codec-native-quic/pom.xml
prop() { sed -n "s:.*<$1>\(.*\)</$1>.*:\1:p" "$pom" | head -n 1; }
fetch() { # <url> <commit> <dir>
  git init -q "$3"
  git -C "$3" fetch -q --depth 1 "$1" "$2"
  git -C "$3" -c advice.detachedHead=false checkout -q FETCH_HEAD
}
target=$src/codec-native-quic/target
mkdir -p "$target"
fetch "$(prop boringsslRepository)" "$(prop boringsslCommitSha)" "$target/boringssl-source"
fetch "$(prop quicheRepository)" "$(prop quicheCommitSha)" "$target/quiche-source"
(cd "$target/quiche-source" && cargo fetch -q)
