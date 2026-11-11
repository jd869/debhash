#!/usr/bin/env bash
# Ingest historical package versions from snapshot.ubuntu.com.
#
# The live mirror only carries the newest version of each package, but CI
# images run whatever was current when they were built. snapshot.ubuntu.com
# serves the archive exactly as it was at a timestamp, so running the same
# ingest against a few timestamps fills in the versions in between. Debs that
# are already indexed are skipped (matched by sha256), so each extra timestamp
# only downloads what changed.
#
# Usage: scripts/backfill-snapshots.sh <attestation.json> [db] [timestamps...]
set -euo pipefail

ATT=${1:?usage: $0 <attestation.json> [db] [YYYYMMDDTHHMMSSZ ...]}
DB=${2:-data/noble-arm64.db}
shift $(( $# >= 2 ? 2 : 1 ))
# Default: around the orjson fixture's build date (2025-12-10).
TIMESTAMPS=("$@")
if [ ${#TIMESTAMPS[@]} -eq 0 ]; then
  TIMESTAMPS=(20251101T000000Z 20251115T000000Z 20251201T000000Z 20251210T000000Z)
fi

SUITE=${SUITE:-noble}
ARCH=${ARCH:-arm64}
# arm64/armhf/riscv64 live on ubuntu-ports; amd64/i386 on ubuntu.
case "$ARCH" in amd64|i386) BASE=https://snapshot.ubuntu.com/ubuntu ;; *) BASE=https://snapshot.ubuntu.com/ubuntu-ports ;; esac

go build -o debhash ./cmd/debhash
failed=()
for ts in "${TIMESTAMPS[@]}"; do
  if ! [[ "$ts" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]; then
    echo "skipping invalid timestamp '$ts' (want YYYYMMDDTHHMMSSZ)" >&2
    failed+=("$ts")
    continue
  fi
  echo "=== snapshot $ts"
  # One unreachable snapshot should not lose the others.
  if ! ./debhash ingest --db "$DB" --mirror "$BASE/$ts" --suite "$SUITE" --arch "$ARCH" \
    --pockets updates,security --components main,universe --workers 6 --paths-from "$ATT"; then
    echo "snapshot $ts failed; continuing" >&2
    failed+=("$ts")
  fi
done
echo
if [ ${#failed[@]} -gt 0 ]; then
  echo "failed snapshots: ${failed[*]}" >&2
fi
./debhash report --db "$DB" --attestation "$ATT" --suite "$SUITE" --arch "$ARCH"
