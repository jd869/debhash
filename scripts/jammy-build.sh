#!/bin/bash
# A small "build" that only uses tools already in the base ubuntu image, so
# every system file it touches comes from that image's own (dated) packages.
# Installing anything with apt would pull today's versions and break that.
# Run under `witness run --trace` by .github/workflows/jammy.yml.
set -euo pipefail

work=$(mktemp -d)
cd "$work"

# Text processing: coreutils, sed, grep, mawk, findutils, diffutils.
printf 'hello from %s\n' "$(. /etc/os-release && echo "$PRETTY_NAME")" > hello.txt
sed 's/hello/goodbye/' hello.txt > goodbye.txt
grep -q goodbye goodbye.txt
awk '{ print length($0) }' hello.txt > lengths.txt
cmp -s hello.txt goodbye.txt || diff hello.txt goodbye.txt > changes.diff || true
find . -type f | sort > manifest.txt

# Archiving and compression: tar, gzip.
tar -cf out.tar hello.txt goodbye.txt manifest.txt
gzip -k out.tar
sha256sum out.tar out.tar.gz > SHA256SUMS
sha256sum -c SHA256SUMS > /dev/null

# Interpreters: perl-base, dash, bash.
perl -e 'printf "perl %vd\n", $^V' > perl.txt
sh -c 'echo dash ok' > dash.txt

# Package tooling: dpkg and apt load libapt-pkg, libstdc++, libgcc-s,
# libzstd, liblz4, libxxhash, libgcrypt, libsystemd and friends.
dpkg --print-architecture > arch.txt
dpkg-query -W -f '${Package}\n' | wc -l > package-count.txt
apt-config dump > /dev/null

ls -la "$work" > listing.txt
echo "build done in $work"
