#!/bin/bash
# Hash every regular file shipped by every installed package and print them as
# JSON ({"files": {"/path": {"sha256": "..."}}}), which `debhash report` and
# `debhash eval` read like an attestation. Together with `dpkg-query -W` this
# gives a real system with known package versions: ground truth for testing.
#
# Uses only tools in the base ubuntu image (no jq, no python).
set -euo pipefail

dpkg-query -W -f '${Package}\n' |
  xargs dpkg -L 2>/dev/null |
  sort -u |
  while IFS= read -r f; do
    # Regular files only: directories have no content and symlinks would hash
    # their target a second time under another name.
    if [ -f "$f" ] && [ ! -L "$f" ]; then
      printf '%s\0' "$f"
    fi
  done |
  xargs -0 -r sha256sum |
  awk '
    BEGIN { printf "{\"files\":{" }
    {
      hash = $1
      path = substr($0, 67)          # sha256sum: 64 hex chars, 2 spaces, path
      gsub(/\\/, "\\\\", path)
      gsub(/"/, "\\\"", path)
      printf "%s\"%s\":{\"sha256\":\"%s\"}", (NR > 1 ? "," : ""), path, hash
    }
    END { print "}}" }
  '
