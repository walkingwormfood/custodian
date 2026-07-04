#!/usr/bin/env python3
"""Custodian provenance record.

An append-only directory of signed, hash-chained JSON entries with
periodic Merkle-root anchoring. No database, no server, no daemon.

Record layout:
    custodian.json          config, written once at init, never modified
    allowed_signers         verification keyring for ssh-keygen -Y verify
    entries/00000001.json   one entry per file, plus a detached .sig
    anchors/00000001.json   Merkle root over entries 1..N, plus .sig,
                            .ots (OpenTimestamps) and .tsaN.tsr (RFC 3161)
    objects/sha256/xx/<hash>  content-addressed copies of archived files

Every claim the record makes is checkable without this tool:
sha256 for the hash chain and Merkle tree (RFC 6962 construction),
`ssh-keygen -Y verify` for signatures, `ots verify` for anchors.
The exact formats are documented in README.md.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

NS_ENTRY = "custodian-entry-v1"
NS_ANCHOR = "custodian-anchor-v1"
CHUNK = 1 << 20


def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canon(obj):
    """Canonical JSON bytes: sorted keys, no spaces, trailing newline.
    Files are written once in this form and hashed as raw bytes thereafter."""
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def file_sha256(path):
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


# ---------------------------------------------------------------- Merkle

def _leaf(data):
    return hashlib.sha256(b"\x00" + data).digest()


def _node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves):
    """RFC 6962 Merkle Tree Hash over a list of leaf byte strings."""
    n = len(leaves)
    if n == 0:
        die("cannot compute a Merkle root over zero entries")
    if n == 1:
        return _leaf(leaves[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return _node(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


# ---------------------------------------------------------------- ssh signing

def find_ots():
    """ots from PATH, falling back to pip's user scripts dir."""
    found = shutil.which("ots")
    if found:
        return found
    import sysconfig
    for scheme in ("nt_user", "posix_user"):
        try:
            candidate = Path(sysconfig.get_path("scripts", scheme)) / (
                "ots.exe" if os.name == "nt" else "ots")
            if candidate.exists():
                return str(candidate)
        except KeyError:
            pass
    return None


def run_ots(ots, argv):
    """Run ots. On Windows its python-bitcoinlib dependency needs an OpenSSL
    DLL findable as ssl.dll on a local (non-UNC) PATH entry; keep a renamed
    copy of Python's own libcrypto next to LOCALAPPDATA and prepend it."""
    env = os.environ.copy()
    if os.name == "nt":
        shim = Path(os.environ["LOCALAPPDATA"]) / "custodian" / "ots-shim"
        dll = shim / "ssl.dll"
        if not dll.exists():
            src = Path(sys.base_prefix) / "DLLs" / "libcrypto-3.dll"
            if src.exists():
                shim.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, dll)
        if dll.exists():
            env["PATH"] = f"{shim};" + env["PATH"]
    return subprocess.run([ots, *argv], capture_output=True, text=True, env=env)


def ssh_keygen():
    exe = shutil.which("ssh-keygen")
    if not exe:
        die("ssh-keygen not found on PATH")
    return exe


def ssh_sign(key, namespace, path):
    # Not captured: hardware keys prompt for touch/PIN on the terminal.
    r = subprocess.run([ssh_keygen(), "-Y", "sign", "-f", str(key), "-n", namespace, str(path)])
    if r.returncode != 0:
        die(f"signing failed for {path}")


def ssh_verify(allowed_signers, identity, namespace, path):
    sig = str(path) + ".sig"
    if not os.path.exists(sig):
        return False, "missing signature file"
    with open(path, "rb") as f:
        r = subprocess.run(
            [ssh_keygen(), "-Y", "verify", "-f", str(allowed_signers),
             "-I", identity, "-n", namespace, "-s", sig],
            stdin=f, capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


# ---------------------------------------------------------------- RFC 3161

_SHA256_ALGID = bytes.fromhex("300d06096086480165030402010500")


def rfc3161_query(digest):
    """DER TimeStampReq: version 1, sha256 imprint, certReq TRUE."""
    imprint = b"\x30\x31" + _SHA256_ALGID + b"\x04\x20" + digest
    body = b"\x02\x01\x01" + imprint + b"\x01\x01\xff"
    return b"\x30" + bytes([len(body)]) + body


def _der_tlv(buf, off):
    tag = buf[off]
    length = buf[off + 1]
    if length < 0x80:
        return tag, off + 2, length
    n = length & 0x7F
    return tag, off + 2 + n, int.from_bytes(buf[off + 2:off + 2 + n], "big")


def rfc3161_stamp(url, file_bytes, out_path):
    """POST a timestamp query for sha256(file_bytes); save the raw .tsr."""
    req = urllib.request.Request(
        url, data=rfc3161_query(hashlib.sha256(file_bytes).digest()),
        headers={"Content-Type": "application/timestamp-query"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        tsr = resp.read()
    tag, off, _ = _der_tlv(tsr, 0)
    if tag != 0x30:
        raise ValueError("response is not a DER sequence")
    tag, off, _ = _der_tlv(tsr, off)          # PKIStatusInfo
    if tag != 0x30:
        raise ValueError("malformed PKIStatusInfo")
    tag, off, _ = _der_tlv(tsr, off)          # status INTEGER
    status = tsr[off]
    if tag != 0x02 or status not in (0, 1):   # granted / grantedWithMods
        raise ValueError(f"TSA refused the request (status {status})")
    with open(out_path, "xb") as f:
        f.write(tsr)


# ---------------------------------------------------------------- record access

def load_record(record_dir):
    root = Path(record_dir)
    cfg_path = root / "custodian.json"
    if not cfg_path.exists():
        die(f"no record at {root} (no custodian.json); run `custodian.py init` first")
    cfg_bytes = cfg_path.read_bytes()
    return root, json.loads(cfg_bytes), cfg_bytes


def numbered(dirpath):
    """Sorted seq numbers of NNNNNNNN.json files; dies on stray files."""
    if not dirpath.exists():
        return []
    seqs = []
    for p in dirpath.iterdir():
        m = re.fullmatch(r"(\d{8})\.json", p.name)
        if m:
            seqs.append(int(m.group(1)))
        elif not re.fullmatch(r"\d{8}\.json\.(sig|ots|tsa\d+\.tsr|ots\.bak)", p.name):
            die(f"unexpected file in {dirpath}: {p.name}")
    return sorted(seqs)


def numbered_path(dirpath, seq):
    return dirpath / f"{seq:08d}.json"


def check_contiguous(seqs, what):
    if seqs != list(range(1, len(seqs) + 1)):
        die(f"{what} are not contiguous from 1: {seqs}")


# ---------------------------------------------------------------- commands

def cmd_init(args):
    root = Path(args.record)
    if (root / "custodian.json").exists():
        die(f"a record already exists at {root}")
    if re.search(r"[\s\"']", args.identity):
        die("identity must not contain whitespace or quotes")
    key = Path(args.key)
    if not key.exists():
        die(f"signing key not found: {key}")

    pub_path = Path(str(key) + ".pub")
    if pub_path.exists():
        pub = pub_path.read_text().strip()
    else:
        r = subprocess.run([ssh_keygen(), "-y", "-f", str(key)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            die(f"could not derive public key: {r.stderr.strip()}")
        pub = r.stdout.strip()
    parts = pub.split()
    if len(parts) < 2:
        die(f"unrecognized public key: {pub}")
    pubkey = f"{parts[0]} {parts[1]}"

    cfg = {
        "v": 1,
        "record_id": secrets.token_hex(16),
        "created": now_utc(),
        "identity": args.identity,
        "signing_key": str(key),
        "pubkey": pubkey,
        "namespaces": {"entry": NS_ENTRY, "anchor": NS_ANCHOR},
        "tsa_urls": args.tsa or [],
    }
    root.mkdir(parents=True, exist_ok=True)
    (root / "entries").mkdir()
    (root / "anchors").mkdir()
    (root / "objects").mkdir()
    with open(root / "custodian.json", "xb") as f:
        f.write(canon(cfg))
    with open(root / "allowed_signers", "x", encoding="utf-8", newline="\n") as f:
        f.write(f'{args.identity} namespaces="{NS_ENTRY},{NS_ANCHOR}" {pubkey}\n')
    print(f"initialized record {cfg['record_id']} at {root}")
    print(f"signer: {args.identity} ({pubkey.split()[0]})")


def signing_key(cfg, args):
    key = Path(args.key) if getattr(args, "key", None) else Path(cfg["signing_key"])
    if not key.exists():
        die(f"signing key not found: {key} (override with --key)")
    return key


def cmd_add(args):
    root, cfg, cfg_bytes = load_record(args.record)
    entries = root / "entries"
    seqs = numbered(entries)
    check_contiguous(seqs, "entries")
    seq = len(seqs) + 1
    prev = sha256_hex(numbered_path(entries, seq - 1).read_bytes()) if seqs else sha256_hex(cfg_bytes)

    files = []
    for name in args.files:
        p = Path(name)
        if not p.is_file():
            die(f"not a file: {p}")
        digest, size = file_sha256(p)
        if args.copy:
            dest = root / "objects" / "sha256" / digest[:2] / digest
            if not dest.exists():
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(p, dest)
        files.append({"name": p.name, "sha256": digest, "size": size,
                      "stored": bool(args.copy)})
    if not args.note and not files:
        die("nothing to add: give -m and/or file paths")

    entry = {"v": 1, "rid": cfg["record_id"], "seq": seq, "prev": prev, "ts": now_utc()}
    if args.note:
        entry["note"] = args.note
    if files:
        entry["files"] = files

    path = numbered_path(entries, seq)
    with open(path, "xb") as f:
        f.write(canon(entry))
    ssh_sign(signing_key(cfg, args), NS_ENTRY, path)
    labels = ([f"note ({len(args.note)} chars)"] if args.note else []) + \
             [f["name"] for f in files]
    print(f"entry {seq}: {', '.join(labels)}")


def cmd_anchor(args):
    root, cfg, _ = load_record(args.record)
    entries, anchors = root / "entries", root / "anchors"
    eseqs = numbered(entries)
    check_contiguous(eseqs, "entries")
    if not eseqs:
        die("no entries to anchor")
    aseqs = numbered(anchors)
    check_contiguous(aseqs, "anchors")

    if aseqs:
        last = json.loads(numbered_path(anchors, aseqs[-1]).read_bytes())
        if last["entries"] >= len(eseqs):
            die(f"anchor {aseqs[-1]} already covers all {len(eseqs)} entries")
        prev = sha256_hex(numbered_path(anchors, aseqs[-1]).read_bytes())
    else:
        prev = None

    leaves = [numbered_path(entries, i).read_bytes() for i in eseqs]
    anchor = {
        "v": 1, "rid": cfg["record_id"], "seq": len(aseqs) + 1, "prev": prev,
        "ts": now_utc(), "entries": len(eseqs), "tree": "rfc6962-sha256",
        "root": merkle_root(leaves).hex(),
    }
    path = numbered_path(anchors, anchor["seq"])
    with open(path, "xb") as f:
        f.write(canon(anchor))
    ssh_sign(signing_key(cfg, args), NS_ANCHOR, path)
    print(f"anchor {anchor['seq']}: root {anchor['root'][:16]}… over entries 1..{anchor['entries']}")

    if args.no_stamp:
        return
    ots = find_ots()
    if ots:
        r = run_ots(ots, ["stamp", str(path)])
        if r.returncode == 0:
            print(f"opentimestamps: pending attestation written ({path.name}.ots);"
                  f" run verify later to upgrade to a Bitcoin proof")
        else:
            print(f"warning: ots stamp failed: {(r.stdout + r.stderr).strip()}", file=sys.stderr)
    else:
        print("warning: ots not installed — anchor is signed but not timestamped"
              " (pip install opentimestamps-client)", file=sys.stderr)
    anchor_bytes = path.read_bytes()
    for i, url in enumerate(cfg.get("tsa_urls", [])):
        out = Path(str(path) + f".tsa{i}.tsr")
        try:
            rfc3161_stamp(url, anchor_bytes, out)
            print(f"rfc3161: token from {url} ({out.name})")
        except Exception as e:
            print(f"warning: RFC 3161 stamp from {url} failed: {e}", file=sys.stderr)


def cmd_verify(args):
    root, cfg, cfg_bytes = load_record(args.record)
    entries, anchors = root / "entries", root / "anchors"
    allowed = root / "allowed_signers"
    identity = cfg["identity"]
    failures, warnings = [], []

    if not allowed.exists():
        failures.append("allowed_signers is missing")
    elif cfg["pubkey"] not in allowed.read_text():
        warnings.append("allowed_signers does not contain the config pubkey")

    eseqs = numbered(entries)
    if eseqs != list(range(1, len(eseqs) + 1)):
        failures.append(f"entries are not contiguous from 1: gaps at "
                        f"{sorted(set(range(1, (eseqs or [0])[-1] + 1)) - set(eseqs))}")
        eseqs = []
    entry_bytes = []
    prev_expected = sha256_hex(cfg_bytes)
    for i in eseqs:
        path = numbered_path(entries, i)
        raw = path.read_bytes()
        entry_bytes.append(raw)
        try:
            obj = json.loads(raw)
        except ValueError:
            failures.append(f"entry {i}: not valid JSON")
            prev_expected = sha256_hex(raw)
            continue
        if obj.get("seq") != i:
            failures.append(f"entry {i}: seq field says {obj.get('seq')}")
        if obj.get("rid") != cfg["record_id"]:
            failures.append(f"entry {i}: record_id mismatch (foreign entry?)")
        if obj.get("prev") != prev_expected:
            failures.append(f"entry {i}: hash chain broken (prev does not match entry {i-1})")
        ok, msg = ssh_verify(allowed, identity, NS_ENTRY, path)
        if not ok:
            failures.append(f"entry {i}: signature invalid ({msg})")
        for f in obj.get("files", []):
            if f.get("stored"):
                opath = root / "objects" / "sha256" / f["sha256"][:2] / f["sha256"]
                if not opath.exists():
                    failures.append(f"entry {i}: stored object {f['name']} missing")
                else:
                    digest, size = file_sha256(opath)
                    if digest != f["sha256"] or size != f["size"]:
                        failures.append(f"entry {i}: stored object {f['name']} does not match its hash")
        prev_expected = sha256_hex(raw)
    print(f"entries: {len(eseqs)} checked")

    aseqs = numbered(anchors)
    if aseqs != list(range(1, len(aseqs) + 1)):
        failures.append(f"anchors are not contiguous from 1: {aseqs}")
        aseqs = []
    ots = find_ots()
    prev_anchor = None
    covered = 0
    for i in aseqs:
        path = numbered_path(anchors, i)
        raw = path.read_bytes()
        try:
            obj = json.loads(raw)
        except ValueError:
            failures.append(f"anchor {i}: not valid JSON")
            prev_anchor = sha256_hex(raw)
            continue
        if obj.get("rid") != cfg["record_id"] or obj.get("seq") != i:
            failures.append(f"anchor {i}: seq/record_id mismatch")
        if obj.get("prev") != prev_anchor:
            failures.append(f"anchor {i}: anchor chain broken")
        n = obj.get("entries", 0)
        if n > len(entry_bytes):
            failures.append(f"anchor {i}: covers {n} entries but only {len(entry_bytes)} exist"
                            f" (entries deleted after anchoring)")
        elif merkle_root(entry_bytes[:n]).hex() != obj.get("root"):
            failures.append(f"anchor {i}: Merkle root mismatch"
                            f" (entries 1..{n} were modified after anchoring)")
        covered = max(covered, n)
        ok, msg = ssh_verify(allowed, identity, NS_ANCHOR, path)
        if not ok:
            failures.append(f"anchor {i}: signature invalid ({msg})")
        ots_path = Path(str(path) + ".ots")
        if ots_path.exists() and ots:
            run_ots(ots, ["upgrade", str(ots_path)])
            r = run_ots(ots, ["verify", str(ots_path)])
            out = (r.stdout + r.stderr).strip().replace("\n", " | ")
            print(f"anchor {i} opentimestamps: {out}")
        elif not ots_path.exists():
            warnings.append(f"anchor {i} has no OpenTimestamps proof")
        elif not ots:
            warnings.append(f"anchor {i} has a .ots proof but ots is not installed to check it")
        prev_anchor = sha256_hex(raw)
    print(f"anchors: {len(aseqs)} checked")

    if len(entry_bytes) > covered:
        warnings.append(f"{len(entry_bytes) - covered} entr{'y is' if len(entry_bytes)-covered==1 else 'ies are'}"
                        f" not yet covered by an anchor (tamper-evidence is weaker until the next anchor)")

    for w in warnings:
        print(f"warning: {w}")
    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        print(f"RESULT: FAILED ({len(failures)} problem{'s' if len(failures) != 1 else ''})")
        sys.exit(1)
    print("RESULT: OK — chain intact, all signatures valid, anchors consistent")


def cmd_status(args):
    root, cfg, _ = load_record(args.record)
    eseqs = numbered(root / "entries")
    aseqs = numbered(root / "anchors")
    covered = 0
    if aseqs:
        covered = json.loads(numbered_path(root / "anchors", aseqs[-1]).read_bytes())["entries"]
    print(f"record {cfg['record_id']} at {root}")
    print(f"signer: {cfg['identity']} ({cfg['pubkey'].split()[0]})")
    if eseqs:
        last = json.loads(numbered_path(root / "entries", eseqs[-1]).read_bytes())
        print(f"entries: {len(eseqs)} (latest {last['ts']})")
    else:
        print("entries: 0")
    print(f"anchors: {len(aseqs)} covering entries 1..{covered}"
          + (f" — {len(eseqs) - covered} unanchored" if len(eseqs) > covered else ""))


def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(prog="custodian.py", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("-C", "--record", default=".", help="record directory (default: current)")

    p = sub.add_parser("init", help="create a new record")
    common(p)
    p.add_argument("--identity", required=True, help="signer name for allowed_signers (no spaces)")
    p.add_argument("--key", required=True, help="path to SSH private key (ed25519-sk stub for hardware keys)")
    p.add_argument("--tsa", action="append", help="RFC 3161 TSA URL to stamp anchors with (repeatable)")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("add", help="append a signed entry")
    common(p)
    p.add_argument("-m", "--note", help="entry text")
    p.add_argument("files", nargs="*", help="files to record (hashed; copied with --copy)")
    p.add_argument("--copy", action="store_true", help="store file copies under objects/")
    p.add_argument("--key", help="override the signing key path from config")
    p.set_defaults(fn=cmd_add)

    p = sub.add_parser("anchor", help="Merkle-root anchor over all entries")
    common(p)
    p.add_argument("--no-stamp", action="store_true", help="skip OpenTimestamps/TSA stamping")
    p.add_argument("--key", help="override the signing key path from config")
    p.set_defaults(fn=cmd_anchor)

    p = sub.add_parser("verify", help="verify the whole record")
    common(p)
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("status", help="show record summary")
    common(p)
    p.set_defaults(fn=cmd_status)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
