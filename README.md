# debhash

Map a file's **sha256** to the **Debian/Ubuntu package and version** that shipped it.

```
sha256:9dd873a9…  →  pkg:deb/ubuntu/libffi8@3.4.6-1build1?arch=arm64&upstream=libffi&distro=ubuntu-24.04
```

Built for [SBOMit](https://github.com/SBOMit/sbomit) ([#43](https://github.com/SBOMit/sbomit/issues/43)).
Witness attestations record a sha256 for every file a build touched. Path regexes can't
attribute system files such as `/lib/aarch64-linux-gnu/libc.so.6`, because their paths
carry no version. Their content hash can.

> **Status: proof of concept.** It indexes Ubuntu noble arm64 for the files in one real
> attestation (results below). The schema, CLI and API are expected to change.

## Results on a real attestation

[`test/orjson_witness.json`](https://github.com/SBOMit/sbomit/blob/master/test/orjson_witness.json) from sbomit: a witness attestation of an orjson build on a GitHub Ubuntu 24.04 arm64 runner, made on 2025-12-10. It is reproduced by the [`backfill`](.github/workflows/backfill.yml) workflow.

| | Current mirror only | + versions live 2025-09-01 to 2025-12-10 (Launchpad) |
|---|---|---|
| Hashable system files matched | 151 / 198 (76%) | **192 / 198 (97%)** |
| Shared libraries matched | 18 / 54 | **54 / 54** |
| Packages identified | 31 | **48** |
| …with an exact version | 23 | **45** |
| `.pyc` attributed via their `.py` source | 578 / 578 | 578 / 578 |
| Distro from the `/etc/os-release` hash | no | **Ubuntu 24.04.3** (`base-files 13ubuntu10.3`) |

- **All 6 remaining misses are files created on the machine**, which no package ships: `/etc/hosts`, `/etc/resolv.conf`, `/etc/ld.so.cache`, `/etc/localtime`, the CA bundle and its `cert.pem` link.
- **3 packages keep more than one candidate version:** `python3-pip`, `python3-setuptools` and `linux-libc-dev`. Their files are pure Python or headers that are identical across those versions, and no rebuilt binary is attested to tell the versions apart.
- **Why history matters:** without it, rebuilt binaries (`libc.so.6`, `libssl.so.3`, `python3.12`) don't match, because the live mirror no longer carries the point release the runner had installed.
- **Source-version propagation:** `libc.so.6` pins `libc6 2.39-0ubuntu8.6`, which also pins `libc-bin` and `libc6-dev` (93 headers that are identical across versions). Likewise, `libssl3t64` pins `openssl`.

## How it works

```
mirror (Release → Packages → pool/*.deb)
   │  stream each .deb: ar → control.tar + data.tar (.zst/.xz/.gz) → sha256 per file
   ▼
SQLite: packages (one row per .deb) · publications (suite/pocket/mirror) · files (path, sha256)
   │
   ├── debhash report   how much of an attestation is attributable
   └── debhash serve    GET /v1/sha256/{h} · POST /v1/bulk/sha256 · /v1/packages/{id}/files · /v1/stats
```

- **Nothing is written to disk but the index.** Each .deb is hashed while it downloads.
- **Integrity, end to end:** Ubuntu's archive key → `Release` → `Packages`/`Contents` → each .deb.
  - `InRelease` (or `Release` + `Release.gpg`) must carry a valid OpenPGP signature from a key in the archive keyring, or the run stops before downloading anything.
  - The Ubuntu archive keyring is embedded (2012 and 2018 archive keys, from the `ubuntu-keyring` package). For other archives, pass `--keyring`, e.g. `/usr/share/keyrings/debian-archive-keyring.gpg`.
  - Index files are checked against the sha256 in the verified `Release`, and every .deb against the sha256 in `Packages`.
  - Debs from Launchpad history are checked against the sha256 Launchpad's API returns over HTTPS. They are not covered by the archive signature, because they are no longer in any signed index.
  - `--no-verify` turns signature checks off; it is only meant for test mirrors.
- **Dedup:** a .deb published in several pockets (or as `Architecture: all`) is downloaded and stored once, with one publication row per location.
- **Targeted ingest** (`--paths-from`) uses the `Contents-<arch>` index (path → package, the same data as `apt-file`) to fetch only the packages that ship a file in the attestation.
  - Merged-`/usr` spellings (`/lib/…` vs `/usr/lib/…`) are both tried.
  - For a generated `__pycache__/*.pyc`, it fetches the package owning the `.py` source.
- **History:** the live mirror only has the newest version of each package, but a build installs whatever was current on its build date. Two sources fill the gap:
  - `--history launchpad --history-after 2025-09-01 --history-before 2025-12-10` asks Launchpad, where Ubuntu builds every package, for each targeted package's versions that were live in that window, then downloads them with their published sha256.
  - Pointing `--mirror` at `https://snapshot.ubuntu.com/ubuntu-ports/<timestamp>` ingests the archive as it was at that moment (`scripts/backfill-snapshots.sh`).
  - Either way, re-runs only download debs that aren't already indexed.

## Quick start

```sh
go build -o debhash ./cmd/debhash

# Index the packages behind one attestation (current noble pockets).
./debhash ingest --db data/noble-arm64.db --suite noble --arch arm64 \
  --paths-from ../sbomit/test/orjson_witness.json

# Add the versions that were live around the build date (2025-12-10).
./debhash ingest --db data/noble-arm64.db --suite noble --arch arm64 \
  --paths-from ../sbomit/test/orjson_witness.json \
  --history launchpad --history-after 2025-09-01 --history-before 2025-12-10

# How much of the attestation does the index attribute?
./debhash report --db data/noble-arm64.db --attestation ../sbomit/test/orjson_witness.json \
  --suite noble --arch arm64

# Serve it.
./debhash serve --db data/noble-arm64.db --addr 127.0.0.1:8080
curl -s localhost:8080/v1/sha256/<sha256>?suite=noble\&arch=arm64
curl -s -XPOST localhost:8080/v1/bulk/sha256 \
  -d '{"hashes":["<sha256>","<sha256>"],"hint":{"distro":"ubuntu","suite":"noble","arch":"arm64"}}'
```

Each ingest logs who signed every Release, e.g. `release noble-updates: signature OK, F6ECB3762474EDA9D21B7022871920D1991BC93C (Ubuntu Archive Automatic Signing Key (2018) <ftpmaster@ubuntu.com>)`.

`debhash inspect file.deb` prints the sha256 of every file in a local .deb. It's useful for checking results against `dpkg-deb -x` + `sha256sum`.

## API

| Endpoint | Returns |
|---|---|
| `GET /v1/sha256/{hash}?distro=&suite=&arch=&limit=` | `{sha256, fanout, candidates[]}`, or 404 |
| `POST /v1/bulk/sha256` `{hashes[≤1000], hint{distro,suite,arch}, limit}` | `{results[], missing[]}` |
| `POST /v1/attribute` `{files[{path,sha256}], hint?}` | identified packages with the files assigned to each, plus the distro/suite/arch used (detected when the hint is empty) |
| `GET /v1/packages/{id}/files` | full file manifest of one .deb |
| `GET /v1/stats` | totals and per-suite coverage with last-ingested time |

- **Filters:** `suite=noble` also matches `noble-updates`, `noble-security` and the other pockets; `arch=arm64` also matches `all`.
- **`fanout`:** the number of distinct package names that ship the same content. Licence texts, CA certificates and locale data are shared by many packages, so a client should not identify a package from a high-fanout file on its own.
- **Each candidate** carries a syft-compatible PURL, so packages found by hash dedupe with packages syft finds in the dpkg database.
- **`/v1/attribute`** is what sbomit calls. When files narrow a package down to several versions (e.g. pure-Python packages whose files didn't change), it returns `exact: false`, a PURL without a version, and the candidate `versions`, rather than guessing.

## Attribution rules (previewed by `report`, to be used by the sbomit client)

1. Detect the distro from the hash of `/etc/os-release`, which `base-files` ships.
2. A file whose candidates all name one package **anchors** that package.
3. A package's version is the **intersection** of the versions allowed by each of its files. Unchanged files allow many versions; rebuilt binaries allow one.
4. Files shipped by more than 5 packages never identify a package on their own.
5. Generated `.pyc` files are attributed by path, via their `.py` source.

## Development

```sh
go test ./...   # unit + end-to-end ingest against an in-process fake mirror
DEBHASH_NETWORK_TESTS=1 go test ./internal/archive/   # also verify the live Ubuntu archive signature
go vet ./...
```

The tests build real .deb files in memory (ar + tar, with gz/xz/zst compression), so no binary fixtures are checked in.
