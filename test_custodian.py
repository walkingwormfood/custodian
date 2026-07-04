#!/usr/bin/env python3
"""Smoke test for custodian.py: builds a record with a throwaway software
key, verifies it, then tampers with it three ways and checks each is caught.

Usage: python test_custodian.py [workdir]
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CUSTODIAN = Path(__file__).parent / "custodian.py"


def run(*argv, cwd=None):
    return subprocess.run([sys.executable, str(CUSTODIAN), *argv],
                          capture_output=True, text=True, cwd=cwd)


def check(label, result, expect_ok=True):
    ok = (result.returncode == 0) == expect_ok
    tag = "PASS" if ok else "FAIL"
    print(f"{tag}: {label}")
    if not ok:
        print(result.stdout)
        print(result.stderr)
        sys.exit(1)
    return result


def main():
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.gettempdir())
    work = Path(tempfile.mkdtemp(prefix="custodian-test-", dir=base))
    record = work / "record"
    key = work / "testkey"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "custodian-test",
                    "-f", str(key), "-q"], check=True)

    check("init", run("init", "-C", str(record), "--identity", "tester", "--key", str(key)))

    doc = work / "draft.txt"
    doc.write_bytes(b"finding: the numbers in exhibit C do not add up\n")
    check("add note", run("add", "-C", str(record), "-m", "session start"))
    check("add file (hash only)", run("add", "-C", str(record), str(doc)))
    check("add file (--copy)", run("add", "-C", str(record), "-m", "archived draft", "--copy", str(doc)))
    check("anchor (unstamped)", run("anchor", "-C", str(record), "--no-stamp"))
    check("add post-anchor note", run("add", "-C", str(record), "-m", "one more, unanchored"))
    check("verify clean record", run("verify", "-C", str(record)))
    check("status", run("status", "-C", str(record)))

    # Tamper 1: modify an anchored entry's content.
    e2 = record / "entries" / "00000002.json"
    orig = e2.read_bytes()
    e2.write_bytes(orig.replace(b"draft.txt", b"other.txt"))
    r = check("tampered entry detected", run("verify", "-C", str(record)), expect_ok=False)
    for needle in ("signature invalid", "hash chain broken", "Merkle root mismatch"):
        assert needle in r.stdout, f"expected '{needle}' in verify output"
    print("PASS: tamper reported as signature + chain + anchor failure")
    e2.write_bytes(orig)

    # Tamper 2a: delete the UNANCHORED tail entry. This is legitimately
    # undetectable from the record alone — the structural limit that the
    # anchor cadence bounds. Verify must still pass.
    e4 = record / "entries" / "00000004.json"
    e4sig = Path(str(e4) + ".sig")
    saved, saved_sig = e4.read_bytes(), e4sig.read_bytes()
    e4.unlink()
    e4sig.unlink()
    check("unanchored-tail deletion is (by design) not detectable",
          run("verify", "-C", str(record)))
    e4.write_bytes(saved)
    e4sig.write_bytes(saved_sig)

    # Tamper 2b: anchor entry 4, then delete it — now it must be caught.
    check("second anchor", run("anchor", "-C", str(record), "--no-stamp"))
    e4.unlink()
    e4sig.unlink()
    r = check("anchored-entry deletion detected", run("verify", "-C", str(record)),
              expect_ok=False)
    assert "deleted after anchoring" in r.stdout
    e4.write_bytes(saved)
    e4sig.write_bytes(saved_sig)

    # Tamper 3: corrupt a stored object.
    entry3 = json.loads((record / "entries" / "00000003.json").read_bytes())
    digest = entry3["files"][0]["sha256"]
    obj = record / "objects" / "sha256" / digest[:2] / digest
    obj_orig = obj.read_bytes()
    obj.write_bytes(obj_orig + b"x")
    check("corrupted object detected", run("verify", "-C", str(record)), expect_ok=False)
    obj.write_bytes(obj_orig)

    check("verify after restoring everything", run("verify", "-C", str(record)))
    print(f"\nall checks passed (workdir kept at {work})")
    if "--clean" in sys.argv:
        shutil.rmtree(work)


if __name__ == "__main__":
    main()
