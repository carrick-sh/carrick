#!/usr/bin/env python3
"""Value-range scan vs two-base relocation ground truth for Go ET_EXEC.

What this measures
------------------
The relocation-route verdict (docs/superpowers/specs/
2026-08-07-goetexec-relocation-route.md, UNSOUND) left ~63% of absolute
sites (packed .rodata) with no enumerating metadata. The challenged
follow-up hypothesis: a relocator does not need metadata — treat every
8-byte-aligned word in the metadata-free regions whose value lies inside
the image's PT_LOAD span [image_base, image_end] as an absolute pointer
and fix it up by +delta. This script settles that hypothesis against
ground truth, per binary:

- Ground truth: the exact absolute-site set from the two-base link diff
  (goetexec_reloc_census.word_diff; same-program pairs built with
  GOTOOLCHAIN-pinned `go build` vs `-ldflags=-T=<base+delta>`).
- Scan domain (what a metadata-augmented relocator would value-scan):
  all 8-aligned words of .rodata and .noptrdata, plus the .data words
  the gcdatamask does NOT cover (mask=1 words are metadata-enumerable).
  Sites outside the domain (.data mask-covered, .itablink, .go.fipsinfo,
  pcHeader.textStart) are credited to known-layout metadata and checked
  for completeness.
- FALSE POSITIVES = scan hits not in ground truth: words a +delta fixup
  would silently corrupt. Each is recorded with symbol, class, byte
  context, and structural forensics (is it the Size_/PtrBytes slot of a
  type descriptor? are its neighbors real pointers? does its value land
  on a symbol boundary?).
- FALSE NEGATIVES = in-domain ground-truth sites the scan misses (value
  outside the PT_LOAD span): words left stale. Recorded with symbol and
  value so fault-catchability (deref -> SIGSEGV vs compare -> silent)
  can be judged.
- Plausibility refinement: re-filter hits requiring the value to land
  exactly on an ELF symbol address or section start; reports FP shrink
  and the new FNs it introduces.

Also scans ALL allocated PROGBITS sections (secondary, for the record)
so accidental in-range integers in .text/.gopclntab are visible, and has
an --exact mode for the unmodified image binaries (no ground truth; scan
profile only, to check the rebuilt twins transfer).

Perturbation: none - static ELF analysis only. Receipts land on stdout
as JSON; redirect to target/perf/goetexec-valuescan/.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import Counter, defaultdict

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import goetexec_reloc_census as census  # noqa: E402

PTR = 8


def pt_load_span(elf: census.Elf) -> tuple[int, int, list[dict]]:
    phoff, = struct.unpack_from("<Q", elf.data, 32)
    phentsize, phnum = struct.unpack_from("<HH", elf.data, 54)
    loads = []
    for i in range(phnum):
        p_type, p_flags = struct.unpack_from("<II", elf.data, phoff + i * phentsize)
        _off, va, _pa, filesz, memsz, _align = struct.unpack_from(
            "<QQQQQQ", elf.data, phoff + i * phentsize + 8
        )
        if p_type == 1:  # PT_LOAD
            loads.append({"va": va, "filesz": filesz, "memsz": memsz, "flags": p_flags})
    base = min(l["va"] for l in loads)
    end = max(l["va"] + l["memsz"] for l in loads)
    return base, end, loads


def data_mask(elf: census.Elf) -> tuple[int, int, list[int]]:
    return census.gc_mask_bits(elf, "data")


def scan_section(elf: census.Elf, sec: census.Section, lo: int, hi: int) -> list[tuple[int, int]]:
    """All 8-aligned words in sec whose value is in [lo, hi]."""
    assert sec.addr % PTR == 0, f"{sec.name} not 8-aligned"
    raw = elf.data[sec.off : sec.off + sec.size]
    hits = []
    for w in range(len(raw) // PTR):
        v = int.from_bytes(raw[w * PTR : w * PTR + PTR], "little")
        if lo <= v <= hi:
            hits.append((sec.addr + w * PTR, v))
    return hits


def sym_starts(elf: census.Elf) -> set[int]:
    s = {value for value, _size, _name in elf.symbols}
    s.update(sec.addr for sec in elf.sections.values() if sec.alloc and sec.size)
    return s


def byte_context(elf: census.Elf, sec: census.Section, va: int) -> str:
    off = sec.off + (va - sec.addr)
    b = elf.data[off : off + PTR]
    ascii_ = "".join(chr(c) if 32 <= c < 127 else "." for c in b)
    return f"{b.hex()} |{ascii_}|"


def forensics(elf: census.Elf, sec: census.Section, va: int, value: int,
              gt_vas: set[int], starts: set[int]) -> dict:
    """Structural facts about one scan hit, for FP classification."""
    out = {
        "prev_is_gt": (va - PTR) in gt_vas,
        "next_is_gt": (va + PTR) in gt_vas,
        "value_on_symbol": value in starts,
        "bytes": byte_context(elf, sec, va),
    }
    # go1.24 abi.Type layout: Size_@0, PtrBytes@8, Equal fn ptr@24,
    # GCData *byte@32 - both pointer slots are ground-truth sites when
    # non-nil. A hit whose va+24 AND va+32 are GT sites is a Size_ slot
    # at a type-descriptor start; va+16/+24 GT => PtrBytes slot.
    out["typedesc_size_slot"] = (va + 24) in gt_vas and (va + 32) in gt_vas
    out["typedesc_ptrbytes_slot"] = (va + 16) in gt_vas and (va + 24) in gt_vas
    return out


def analyze_pair(base_path: str, high_path: str, name: str, max_dump: int) -> dict:
    base = census.parse_elf(base_path)
    high = census.parse_elf(high_path)
    delta = high.sections[".text"].addr - base.sections[".text"].addr
    img_lo, img_hi, loads = pt_load_span(base)
    out: dict = {
        "mode": "pair",
        "name": name,
        "base": base_path,
        "high": high_path,
        "delta": hex(delta),
        "image_range": [hex(img_lo), hex(img_hi)],
        "pt_loads": [{k: hex(v) if k != "flags" else v for k, v in l.items()} for l in loads],
    }

    # ---- ground truth ----
    diff = census.word_diff(base, high, delta)
    gt_all = {(s["section"], s["va"]): s["value"] for s in diff["sites"]}
    gt_by_sec: dict[str, dict[int, int]] = defaultdict(dict)
    for (sec, va), v in gt_all.items():
        gt_by_sec[sec][va] = v
    out["ground_truth"] = {
        "total": len(gt_all),
        "by_section": {k: len(v) for k, v in sorted(gt_by_sec.items())},
        "other_diffs": len(diff["other_diffs"]),
    }

    # ---- metadata-covered set (outside the scan domain) ----
    dstart, dend, dbits = data_mask(base)
    def mask_bit(va: int) -> int:
        idx = (va - dstart) // PTR
        return dbits[idx] if dstart <= va < dend and idx < len(dbits) else 0

    meta_cover: Counter = Counter()
    meta_uncovered = []
    for (sec, va), v in gt_all.items():
        if sec == ".data" and mask_bit(va):
            meta_cover["gcdatamask"] += 1
        elif sec == ".itablink":
            meta_cover["itablink-slice"] += 1
        elif sec == ".go.fipsinfo":
            meta_cover["fipsinfo-layout"] += 1
        elif sec == ".gopclntab":
            meta_cover["pcheader-textstart"] += 1
        elif sec in (".rodata", ".noptrdata", ".data"):
            pass  # scan domain
        else:
            meta_uncovered.append({"section": sec, "va": hex(va)})
    out["metadata_covered"] = dict(meta_cover)
    out["gt_outside_domain_and_metadata"] = meta_uncovered

    # ---- the value-range scan over the domain ----
    starts = sym_starts(base)
    regions = census.runtime_regions(base)
    gt_vas_all = {va for (_s, va) in gt_all}

    domain_secs = [".rodata", ".noptrdata", ".data"]
    scan_hits: dict[str, list[tuple[int, int]]] = {}
    for sname in domain_secs:
        sec = base.sections.get(sname)
        if sec is None or sec.size == 0:
            scan_hits[sname] = []
            continue
        hits = scan_section(base, sec, img_lo, img_hi)
        if sname == ".data":  # domain = gcdatamask gaps only
            hits = [(va, v) for va, v in hits if not mask_bit(va)]
        scan_hits[sname] = hits

    fp_list, fn_list = [], []
    tp = 0
    fp_class: Counter = Counter()
    for sname in domain_secs:
        sec = base.sections.get(sname)
        gt_here = {
            va: v for va, v in gt_by_sec.get(sname, {}).items()
            if not (sname == ".data" and mask_bit(va))
        }
        hit_vas = {va for va, _ in scan_hits[sname]}
        for va, v in scan_hits[sname]:
            if va in gt_here:
                tp += 1
            else:
                sym = census.sym_at(base, va)
                cls = census.classify(sym, sname, va, regions)
                fp_class[f"{sname}:{cls}"] += 1
                fp_list.append({
                    "section": sname, "va": hex(va), "value": hex(v), "sym": sym,
                    "class": cls, **forensics(base, sec, va, v, gt_vas_all, starts),
                })
        for va, v in gt_here.items():
            if va not in hit_vas:
                sym = census.sym_at(base, va)
                fn_list.append({
                    "section": sname, "va": hex(va), "value": hex(v), "sym": sym,
                    "why": "value-outside-image" if not (img_lo <= v <= img_hi) else "va-unaligned-or-bug",
                })

    out["scan"] = {
        "domain_words_scanned": {
            s: (base.sections[s].size // PTR if s in base.sections else 0) for s in domain_secs
        },
        "hits_by_section": {s: len(h) for s, h in scan_hits.items()},
        "true_positives": tp,
        "false_positives": len(fp_list),
        "false_negatives": len(fn_list),
        "fp_by_class": dict(fp_class.most_common()),
    }
    out["false_positives"] = fp_list[:max_dump]
    out["false_negatives"] = fn_list[:max_dump]

    # ---- plausibility refinement: value must land on a symbol/section start ----
    fp2 = [f for f in fp_list if int(f["value"], 16) in starts]
    new_fn = 0
    for sname in domain_secs:
        for va, v in gt_by_sec.get(sname, {}).items():
            if sname == ".data" and mask_bit(va):
                continue
            if img_lo <= v <= img_hi and v not in starts:
                new_fn += 1
    out["plausibility_filter"] = {
        "rule": "value must equal an ELF symbol address or section start",
        "fp_remaining": len(fp2),
        "fp_removed": len(fp_list) - len(fp2),
        "new_false_negatives": new_fn,
    }

    # ---- secondary: raw scan of every alloc PROGBITS section ----
    raw_counts = {}
    for sname, sec in base.sections.items():
        if not (sec.alloc and sec.progbits and sec.size) or sec.addr % PTR:
            continue
        hits = scan_section(base, sec, img_lo, img_hi)
        gt_here = set(gt_by_sec.get(sname, {}))
        raw_counts[sname] = {
            "hits": len(hits),
            "gt": len(gt_here),
            "non_gt_hits": sum(1 for va, _ in hits if va not in gt_here),
        }
    out["all_sections_raw_scan"] = raw_counts
    return out


def analyze_exact(path: str, max_dump: int) -> dict:
    elf = census.parse_elf(path)
    img_lo, img_hi, loads = pt_load_span(elf)
    dstart, dend, dbits = data_mask(elf)
    out: dict = {
        "mode": "exact", "path": path,
        "elf_type": {2: "ET_EXEC", 3: "ET_DYN"}.get(elf.et, elf.et),
        "image_range": [hex(img_lo), hex(img_hi)],
    }
    hits = {}
    for sname in (".rodata", ".noptrdata", ".data"):
        sec = elf.sections.get(sname)
        if sec is None or sec.size == 0:
            continue
        h = scan_section(elf, sec, img_lo, img_hi)
        if sname == ".data":
            h = [
                (va, v) for va, v in h
                if not (dstart <= va < dend and (va - dstart) // PTR < len(dbits)
                        and dbits[(va - dstart) // PTR])
            ]
        hits[sname] = len(h)
    out["scan_hits"] = hits
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pair", nargs=3, action="append", default=[],
                    metavar=("NAME", "BASE", "HIGH"))
    ap.add_argument("--exact", action="append", default=[])
    ap.add_argument("--max-dump", type=int, default=4000,
                    help="cap on per-binary FP/FN detail records in the JSON")
    args = ap.parse_args()
    results = []
    for name, b, h in args.pair:
        results.append(analyze_pair(b, h, name, args.max_dump))
    for p in args.exact:
        results.append(analyze_exact(p, args.max_dump))
    if not results:
        ap.error("need --pair or --exact")
    json.dump(results, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
