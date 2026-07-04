# Custodian — provenance record

A tamper-evident, independently verifiable record of your own work:
signed, hash-chained JSON entries with periodic Merkle-root anchoring to
Bitcoin (OpenTimestamps) and optional RFC 3161 timestamp authorities.
One Python file, no database, no server, no daemon. This is the first
component of the Custodian design; the release machinery (encryption,
timelock, share distribution) is not built yet.

## Requirements

- Python ≥ 3.9 (standard library only — `custodian.py` has no Python dependencies)
- OpenSSH ≥ 8.2 (`ssh-keygen -Y sign/verify`; ≥ 8.2 for hardware `ed25519-sk` keys).
  Ships with Windows 10+, macOS, and every mainstream Linux.
- Optional: [opentimestamps-client](https://github.com/opentimestamps/opentimestamps-client)
  (`pip install opentimestamps-client`) for Bitcoin anchoring. Without it,
  records are still signed and hash-chained; anchors are still signed
  Merkle roots, just not timestamped.

There is no build step. The tool is one file; copy it or clone the repo.
Nothing about a record depends on this tool being installed — see
"Formats" below for how to verify a record with ssh-keygen and sha256 alone.

## Quickstart

```
python custodian.py init -C <record-dir> --identity <yourname> --key <path-to-ssh-private-key>
python custodian.py add  -C <record-dir> -m "what happened today" notes.md exhibit.pdf --copy
python custodian.py anchor -C <record-dir>
python custodian.py verify -C <record-dir>
python custodian.py status -C <record-dir>
```

- The key can be any SSH key; for the design's intent use a hardware-resident
  `ed25519-sk` key (`ssh-keygen -t ed25519-sk`) so every entry takes a touch.
- `add` records file hashes; `--copy` also stores the file itself under
  `objects/` (content-addressed by sha256).
- `anchor` computes a Merkle root over all entries, signs it, and submits it
  to the OpenTimestamps calendars. The Bitcoin attestation completes in
  ~1–2 hours; `verify` upgrades pending proofs automatically.
- To also get an immediate RFC 3161 token per anchor (covering the Bitcoin
  confirmation gap), init with `--tsa https://freetsa.org/tsr` (repeatable).

## Record layout

```
custodian.json          config — written once at init, never modified
allowed_signers         keyring for ssh-keygen -Y verify
entries/00000001.json   one entry per file + detached .sig
anchors/00000001.json   anchor + .sig + .ots (+ .tsaN.tsr)
objects/sha256/xx/<hash>  stored file copies
```

## Formats (verifiable without this tool)

All JSON files are canonical: UTF-8, sorted keys, `,`/`:` separators, one
trailing newline. Hashes are always over the file's raw bytes.

**Entry** — `{"v":1, "rid":<record id>, "seq":N, "prev":<sha256 hex>,
"ts":<UTC ISO 8601>, "note":..., "files":[{"name","sha256","size","stored"}]}`.
`prev` is the sha256 of the previous entry file's bytes; entry 1 chains to
the sha256 of `custodian.json`, binding the record identity and signer key
into the chain.

**Signature** — `ssh-keygen -Y sign` detached signature over the entry file,
namespace `custodian-entry-v1` (anchors: `custodian-anchor-v1`). Check with:

```
ssh-keygen -Y verify -f allowed_signers -I <identity> -n custodian-entry-v1 \
    -s entries/00000001.json.sig < entries/00000001.json
```

**Anchor** — `{"v":1, "rid", "seq", "prev":<sha256 of previous anchor file>,
"ts", "entries":N, "tree":"rfc6962-sha256", "root":<hex>}`. The root is the
RFC 6962 Merkle Tree Hash over the raw bytes of entry files 1..N
(leaf = sha256(0x00‖data), node = sha256(0x01‖left‖right)). The `.ots`
proves the anchor file existed before a Bitcoin block time
(`ots verify anchors/00000001.json.ots`); the `.tsr` is a DER RFC 3161
token over the anchor file's sha256 (verifiable with
`openssl ts -verify`).

## What verification proves, and what it can't

- Any modification or deletion of an anchored entry is detected (signature,
  hash chain, and Merkle root all break), and the anchor timestamp proves
  the original existed before a specific time.
- Truncating the **unanchored tail** (entries added since the last anchor)
  is not detectable from the record alone. Anchor cadence bounds this
  window. Giving the latest anchor to another party (planned for the
  heartbeat step of the design) closes it against everyone but yourself.
- Timestamps prove **existence before a time**, not authorship; signatures
  prove authorship by the key, not the time. Together: this signer had this
  exact content by this time.

## Windows note

The `ots` client's `python-bitcoinlib` dependency needs an OpenSSL DLL it
can find as `ssl.dll`. `custodian.py` handles this automatically by keeping
a renamed copy of Python's own `libcrypto-3.dll` in
`%LOCALAPPDATA%\custodian\ots-shim` and prepending it to PATH when it runs
`ots`. On Linux nothing special is needed.

## Test

```
python test_custodian.py
```

Builds a throwaway record, verifies it, then tampers with it three ways
(entry modification, anchored-entry deletion, object corruption) and checks
each is caught — and that unanchored-tail truncation correctly is not.
Uses a throwaway software key and no network; safe to run anywhere.

## License

MIT — see [LICENSE](LICENSE).
