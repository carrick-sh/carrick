#!/usr/bin/env python3
"""Go ET_EXEC load-time-relocation census: is every absolute VA enumerable?

What this measures
------------------
The soundness question behind relocating an unmodified Go ET_EXEC linux/arm64
binary above Darwin's 4 GiB __PAGEZERO floor (docs/superpowers/specs/
2026-08-07-goetexec-relocation-route.md): which words in the binary are
link-base-dependent (must be fixed up by +delta), and which of those a loader
could enumerate WITHOUT relocation records.

Two modes:

1. diff mode (--base A --high B): A and B are the SAME Go program linked at two
   text bases delta apart (go build vs go build -ldflags=-T=<base+delta>).
   Every allocated section is size-identical; a word-by-word diff of section
   contents is EXACT ground truth for base-dependence: a 64-bit word that
   differs by exactly delta is an absolute-address site; any other difference
   is flagged separately (expected only in the content-hash build/tool IDs).
   Sites are attributed to their containing ELF symbol and bucketed by class
   (type metadata, itabs, funcval records, stmps, moduledata, pclntab header,
   jump tables, ...). For .data sites the script also decodes the runtime's
   own GC program at runtime.gcdata (the moduledata gcdatamask bitmap,
   go1.24 runtime/mbitmap.go runGCProg encoding: 00=stop, 0nnnnnnn=literal,
   1nnnnnnn c / 10000000 n c=repeat) and reports which absolute sites the GC
   bitmap covers vs misses.

2. census mode (--exact BIN): a single binary (e.g. the exact toolchain
   binaries pulled from the conformance image) — verifies ET_EXEC/no-reloc
   facts, decodes the GC program, and reports the class profile (data pointer
   words, itab count, symbol classes) so diff-mode ground truth measured on a
   locally rebuilt twin can be argued to transfer.

Perturbation: none — purely static ELF analysis, no guest or host runs.
Receipts land on stdout as JSON; redirect to target/perf/goetexec-reloc/.
"""

from __future__ import annotations

import argparse
import bisect
import json
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field


PTR = 8


@dataclass
class Section:
    name: str
    sh_type: int
    flags: int
    addr: int
    off: int
    size: int

    @property
    def alloc(self) -> bool:
        return bool(self.flags & 0x2)

    @property
    def progbits(self) -> bool:
        return self.sh_type == 1  # SHT_PROGBITS


@dataclass
class Elf:
    path: str
    data: bytes
    et: int
    machine: int
    entry: int
    sections: dict[str, Section] = field(default_factory=dict)
    symbols: list[tuple[int, int, str]] = field(default_factory=list)  # (value, size, name)
    sym_by_name: dict[str, tuple[int, int]] = field(default_factory=dict)


def parse_elf(path: str) -> Elf:
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise SystemExit(f"{path}: not a 64-bit LE ELF")
    et, machine = struct.unpack_from("<HH", data, 16)
    entry, _phoff, shoff = struct.unpack_from("<QQQ", data, 24)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_off = struct.unpack_from("<Q", data, shoff + shstrndx * shentsize + 24)[0]
    elf = Elf(path=path, data=data, et=et, machine=machine, entry=entry)
    raw_sections = []
    for i in range(shnum):
        nameoff, s_type = struct.unpack_from("<II", data, shoff + i * shentsize)
        end = data.index(b"\0", shstr_off + nameoff)
        nm = data[shstr_off + nameoff : end].decode()
        flags, addr, off, size = struct.unpack_from("<QQQQ", data, shoff + i * shentsize + 8)
        link, _info = struct.unpack_from("<II", data, shoff + i * shentsize + 40)
        sec = Section(nm, s_type, flags, addr, off, size)
        elf.sections[nm] = sec
        raw_sections.append((sec, link))
    # symtab
    for sec, link in raw_sections:
        if sec.sh_type == 2:  # SHT_SYMTAB
            stroff = raw_sections[link][0].off
            count = sec.size // 24
            for i in range(count):
                base = sec.off + i * 24
                st_name, _info, _other, _shndx = struct.unpack_from("<IBBH", data, base)
                st_value, st_size = struct.unpack_from("<QQ", data, base + 8)
                if st_name == 0:
                    continue
                end = data.index(b"\0", stroff + st_name)
                nm = data[stroff + st_name : end].decode(errors="replace")
                elf.symbols.append((st_value, st_size, nm))
                elf.sym_by_name.setdefault(nm, (st_value, st_size))
    elf.symbols.sort()
    return elf


def sym_at(elf: Elf, va: int) -> str:
    idx = bisect.bisect_right(elf.symbols, (va, 1 << 63, "￿")) - 1
    while idx >= 0:
        value, size, name = elf.symbols[idx]
        if value <= va < value + max(size, 1):
            return name
        # zero-size symbols stack at the same address; walk back a little
        if value + size <= va and va - value > 0x100000:
            break
        idx -= 1
    return "<no-symbol>"


def run_gc_prog(prog: bytes) -> list[int]:
    """Decode a Go GC program (runtime/mbitmap.go runGCProg encoding) into a
    list of bits, one per pointer-word."""
    bits: list[int] = []
    p = 0

    def varint() -> int:
        nonlocal p
        out = 0
        shift = 0
        while True:
            x = prog[p]
            p += 1
            out |= (x & 0x7F) << shift
            if x & 0x80 == 0:
                return out
            shift += 7

    while True:
        inst = prog[p]
        p += 1
        n = inst & 0x7F
        if inst & 0x80 == 0:
            if n == 0:
                return bits
            for i in range(n):
                byte = prog[p + i // 8]
                bits.append((byte >> (i % 8)) & 1)
            p += (n + 7) // 8
        else:
            if n == 0:
                n = varint()
            c = varint()
            pattern = bits[-n:]
            bits.extend(pattern * c)


def classify(sym: str, sec: str, va: int, regions: dict[str, tuple[int, int]]) -> str:
    if sec == ".itablink":
        return "itablink-slice"
    if sec == ".gopclntab":
        return "pclntab-header"
    if sym.startswith("go:itab."):
        return "itab"
    if sym.startswith("type:") or sym.startswith("type.."):
        return "type-metadata"
    if "·f" in sym or sym.endswith("-fm"):
        return "funcval-record"
    if ".stmp_" in sym or "..stmp_" in sym:
        return "stmp-composite"
    if sym.startswith("go:string"):
        return "string-data"
    if sym.startswith("runtime.firstmoduledata") or sym.startswith("runtime.moduledata"):
        return "moduledata"
    if ".jump" in sym:
        return "jump-table"
    for rname, (lo, hi) in regions.items():
        if lo <= va < hi:
            return f"{rname}{'' if sym == '<no-symbol>' else '-named'}"
    if sym == "<no-symbol>":
        return "unattributed"
    return "other-named"


def runtime_regions(elf: Elf) -> dict[str, tuple[int, int]]:
    """Bound the linker-defined blobs symbols do not subdivide."""
    regions = {}
    def rng(name, lo_sym, hi_sym):
        lo = elf.sym_by_name.get(lo_sym)
        hi = elf.sym_by_name.get(hi_sym)
        if lo and hi:
            regions[name] = (lo[0], hi[0])
    rng("types-region", "runtime.types", "runtime.etypes")
    gofunc = elf.sym_by_name.get("go:func.*")
    if gofunc:
        # go:func.* is a zero-size marker; it ends where the next linker
        # landmark begins (runtime.gcdata for linux/arm64 layout) — bound it
        # by the nearest following symbol with a distinct address.
        idx = bisect.bisect_right(elf.symbols, (gofunc[0], 1 << 63, "￿"))
        end = gofunc[0]
        for value, size, name in elf.symbols[idx:]:
            if value > gofunc[0]:
                end = value
                break
        regions["gofunc-region"] = (gofunc[0], end)
    return regions


def word_diff(base: Elf, high: Elf, delta: int) -> dict:
    report: dict = {"delta": hex(delta), "sections": {}, "sites": [], "other_diffs": []}
    for name, bsec in base.sections.items():
        hsec = high.sections.get(name)
        if hsec is None or not bsec.alloc or not bsec.progbits or bsec.size == 0:
            continue
        if bsec.size != hsec.size:
            report["sections"][name] = {"error": "size mismatch", "base": bsec.size, "high": hsec.size}
            continue
        bbytes = base.data[bsec.off : bsec.off + bsec.size]
        hbytes = high.data[hsec.off : hsec.off + hsec.size]
        if hsec.addr - bsec.addr != delta:
            report["sections"][name] = {"error": "addr delta mismatch"}
            continue
        sites = []
        others = []
        n_words = bsec.size // PTR
        for w in range(n_words):
            off = w * PTR
            bw = bbytes[off : off + PTR]
            hw = hbytes[off : off + PTR]
            if bw == hw:
                continue
            bv = int.from_bytes(bw, "little")
            hv = int.from_bytes(hw, "little")
            va = bsec.addr + off
            if (hv - bv) % (1 << 64) == delta:
                sites.append((va, bv))
            else:
                others.append((va, bv, hv))
        # trailing bytes (< 8) diff check
        tail = bsec.size - n_words * PTR
        if tail and bbytes[-tail:] != hbytes[-tail:]:
            others.append((bsec.addr + n_words * PTR, -1, -1))
        report["sections"][name] = {"abs_sites": len(sites), "other_diffs": len(others)}
        for va, bv in sites:
            report["sites"].append({"section": name, "va": va, "value": bv})
        for va, bv, hv in others:
            report["other_diffs"].append(
                {"section": name, "va": hex(va), "base": hex(bv), "high": hex(hv), "sym": sym_at(base, va)}
            )
    return report


def gc_mask_bits(elf: Elf, which: str) -> tuple[int, int, list[int]]:
    """Decode runtime.gcdata/gcbss program; returns (start, end, bits)."""
    start, _ = elf.sym_by_name[f"runtime.{which}"]
    end, _ = elf.sym_by_name[f"runtime.e{which}"]
    prog_va, _ = elf.sym_by_name[f"runtime.gc{which}"]
    # locate the prog bytes in whatever section holds them
    for sec in elf.sections.values():
        if sec.alloc and sec.progbits and sec.addr <= prog_va < sec.addr + sec.size:
            prog = elf.data[sec.off + (prog_va - sec.addr) : sec.off + sec.size]
            bits = run_gc_prog(prog)
            return start, end, bits
    raise SystemExit(f"gc{which} program not found in any section")


def analyze_pair(base_path: str, high_path: str) -> dict:
    base = parse_elf(base_path)
    high = parse_elf(high_path)
    text_b = base.sections[".text"].addr
    text_h = high.sections[".text"].addr
    delta = text_h - text_b
    out = {"mode": "diff", "base": base_path, "high": high_path}
    out["elf"] = {
        "type": {2: "ET_EXEC", 3: "ET_DYN"}.get(base.et, base.et),
        "machine": base.machine,
        "rel_sections": [n for n in base.sections if n.startswith(".rel")],
        "text_base": hex(text_b),
    }
    diff = word_diff(base, high, delta)
    out["delta"] = hex(delta)

    # attribute + classify
    by_class: Counter = Counter()
    by_section: Counter = Counter()
    class_examples: dict[str, list] = defaultdict(list)
    target_ranges = {
        name: (s.addr, s.addr + s.size) for name, s in base.sections.items() if s.alloc
    }
    regions = runtime_regions(base)
    target_counter: Counter = Counter()
    data_sites = []
    for site in diff["sites"]:
        sym = sym_at(base, site["va"])
        cls = classify(sym, site["section"], site["va"], regions)
        by_class[cls] += 1
        by_section[site["section"]] += 1
        if len(class_examples[cls]) < 8:
            class_examples[cls].append(f"{sym}@{site['va']:#x}->{site['value']:#x}")
        for name, (lo, hi) in target_ranges.items():
            if lo <= site["value"] < hi:
                target_counter[name] += 1
                break
        else:
            target_counter["<outside-image>"] += 1
        if site["section"] == ".data":
            data_sites.append(site["va"])

    # GC data mask coverage of .data absolute sites
    site_value = {s["va"]: s["value"] for s in diff["sites"]}
    dstart, dend, dbits = gc_mask_bits(base, "data")
    covered = uncovered = 0
    uncovered_syms: Counter = Counter()
    uncovered_targets: Counter = Counter()
    for va in data_sites:
        idx = (va - dstart) // PTR
        if idx < len(dbits) and dbits[idx]:
            covered += 1
        else:
            uncovered += 1
            uncovered_syms[sym_at(base, va)] += 1
            v = site_value[va]
            for name, (lo, hi) in target_ranges.items():
                if lo <= v < hi:
                    uncovered_targets[name] += 1
                    break
            else:
                uncovered_targets["<outside-image>"] += 1
    bstart, bend, bbits = gc_mask_bits(base, "bss")

    out["totals"] = {
        "abs_sites": len(diff["sites"]),
        "other_diffs": len(diff["other_diffs"]),
        "by_section": dict(by_section.most_common()),
        "by_class": dict(by_class.most_common()),
        "value_targets": dict(target_counter.most_common()),
    }
    out["class_examples"] = {k: v for k, v in class_examples.items()}
    out["other_diffs"] = diff["other_diffs"][:40]
    out["gcdata"] = {
        "range": [hex(dstart), hex(dend)],
        "ptr_words_in_mask": sum(dbits),
        "mask_words": len(dbits),
        "data_abs_sites": len(data_sites),
        "covered_by_mask": covered,
        "uncovered_by_mask": uncovered,
        "uncovered_syms": dict(uncovered_syms.most_common(20)),
        "uncovered_value_targets": dict(uncovered_targets.most_common()),
    }
    out["regions"] = {k: [hex(lo), hex(hi)] for k, (lo, hi) in regions.items()}
    out["gcbss"] = {
        "range": [hex(bstart), hex(bend)],
        "ptr_words_in_mask": sum(bbits),
        "note": "SHT_NOBITS: bss carries no file bytes, no baked pointers possible",
    }
    return out


def analyze_exact(path: str) -> dict:
    elf = parse_elf(path)
    out = {"mode": "census", "path": path}
    out["elf"] = {
        "type": {2: "ET_EXEC", 3: "ET_DYN"}.get(elf.et, elf.et),
        "machine": elf.machine,
        "entry": hex(elf.entry),
        "rel_sections": [n for n in elf.sections if n.startswith(".rel")],
        "has_symtab": ".symtab" in elf.sections,
        "text_base": hex(elf.sections[".text"].addr),
    }
    dstart, dend, dbits = gc_mask_bits(elf, "data")
    bstart, bend, bbits = gc_mask_bits(elf, "bss")
    itab = elf.sections.get(".itablink")
    out["gcdata"] = {
        "range": [hex(dstart), hex(dend)],
        "mask_words": len(dbits),
        "ptr_words_in_mask": sum(dbits),
    }
    out["gcbss"] = {"range": [hex(bstart), hex(bend)], "ptr_words_in_mask": sum(bbits)}
    out["itablinks"] = itab.size // PTR if itab else 0
    # symbol class census over rodata
    ro = elf.sections[".rodata"]
    regions = runtime_regions(elf)
    cls: Counter = Counter()
    for value, size, name in elf.symbols:
        if ro.addr <= value < ro.addr + ro.size:
            cls[classify(name, ".rodata", value, regions)] += 1
    out["rodata_symbol_classes"] = dict(cls.most_common())
    out["regions"] = {k: [hex(lo), hex(hi)] for k, (lo, hi) in regions.items()}
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base")
    ap.add_argument("--high")
    ap.add_argument("--exact", action="append", default=[])
    args = ap.parse_args()
    results = []
    if args.base and args.high:
        results.append(analyze_pair(args.base, args.high))
    for p in args.exact:
        results.append(analyze_exact(p))
    if not results:
        ap.error("need --base/--high or --exact")
    json.dump(results, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
