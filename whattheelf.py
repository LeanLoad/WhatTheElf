#!/usr/bin/env python3
"""Generate malformed ELF files and check loader/tool crash behavior."""

from __future__ import annotations

import argparse
import json
import os
import signal
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ET_EXEC = 2
EM_X86_64 = 62
EV_CURRENT = 1
PT_LOAD = 1
PT_INTERP = 3
PF_X = 1
PF_R = 4
SHT_SYMTAB = 2

EHDR_SIZE = 64
PHDR_SIZE = 56
SHDR_SIZE = 64
BASE = 0x400000


@dataclass(frozen=True)
class Fixture:
    name: str
    description: str
    data: bytes
    executable: bool = True


def ehdr(
    *,
    entry: int = BASE + 0x80,
    phoff: int = EHDR_SIZE,
    shoff: int = 0,
    phnum: int = 1,
    shnum: int = 0,
    shstrndx: int = 0,
) -> bytes:
    ident = bytearray(16)
    ident[0:4] = b"\x7fELF"
    ident[4] = 2  # ELFCLASS64
    ident[5] = 1  # ELFDATA2LSB
    ident[6] = EV_CURRENT
    return struct.pack(
        "<16sHHIQQQIHHHHHH",
        bytes(ident),
        ET_EXEC,
        EM_X86_64,
        EV_CURRENT,
        entry,
        phoff,
        shoff,
        0,
        EHDR_SIZE,
        PHDR_SIZE,
        phnum,
        SHDR_SIZE,
        shnum,
        shstrndx,
    )


def phdr(p_type: int, flags: int, offset: int, vaddr: int, filesz: int, memsz: int, align: int = 0x1000) -> bytes:
    return struct.pack("<IIQQQQQQ", p_type, flags, offset, vaddr, vaddr, filesz, memsz, align)


def shdr(sh_type: int = 0, offset: int = 0, size: int = 0, link: int = 0, entsize: int = 0) -> bytes:
    return struct.pack("<IIQQQQIIQQ", 0, sh_type, 0, 0, offset, size, link, 0, 0, entsize)


def pad(buf: bytearray, size: int) -> None:
    if len(buf) < size:
        buf.extend(b"\0" * (size - len(buf)))


def base_exec(phdrs: list[bytes], *, shoff: int = 0, shnum: int = 0, shdrs: bytes = b"") -> bytes:
    buf = bytearray(ehdr(phnum=len(phdrs), shoff=shoff, shnum=shnum))
    for p in phdrs:
        buf += p
    pad(buf, 0x80)
    buf += b"\xb8\x3c\x00\x00\x00\xbf\x2a\x00\x00\x00\x0f\x05"  # exit(42)
    if shdrs:
        pad(buf, shoff)
        buf += shdrs
    return bytes(buf)


def fixtures() -> list[Fixture]:
    return [
        Fixture(
            "control_exit42",
            "valid tiny x86-64 ET_EXEC that exits 42",
            base_exec([phdr(PT_LOAD, PF_R | PF_X, 0, BASE, 0x8C, 0x8C)]),
        ),
        Fixture(
            "qemu_phnum0",
            "ELF header with e_phnum = 0",
            ehdr(phnum=0) + b"\0" * 0x100,
        ),
        Fixture(
            "qemu_interp_filesz0",
            "PT_INTERP with p_filesz = 0",
            base_exec([
                phdr(PT_LOAD, PF_R | PF_X, 0, BASE, 0x8C, 0x8C),
                phdr(PT_INTERP, PF_R, 0x180, 0, 0, 0, 1),
            ]),
        ),
        Fixture(
            "qemu_filesz_gt_memsz",
            "PT_LOAD with p_filesz > p_memsz",
            base_exec([phdr(PT_LOAD, PF_R | PF_X, 0, BASE, 0x3000, 0x1000)]),
        ),
        Fixture(
            "qemu_symtab_bad_shlink",
            "SHT_SYMTAB.sh_link points outside the section table",
            base_exec(
                [phdr(PT_LOAD, PF_R | PF_X, 0, BASE, 0x8C, 0x8C)],
                shoff=0x200,
                shnum=2,
                shdrs=shdr() + shdr(SHT_SYMTAB, offset=0x300, size=24, link=0x1000000, entsize=24),
            ),
        ),
    ]


def generate(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for fx in fixtures():
        path = out_dir / fx.name
        path.write_bytes(fx.data)
        if fx.executable:
            os.chmod(path, 0o755)
        manifest.append({"name": fx.name, "description": fx.description, "size": len(fx.data)})
        print(path)
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def command_for(template: list[str], path: Path) -> list[str]:
    if any(arg == "{}" for arg in template):
        return [str(path) if arg == "{}" else arg for arg in template]
    return [*template, str(path)]


def verdict(returncode: int | None) -> str:
    if returncode is None:
        return "TIMEOUT"
    if returncode < 0:
        sig = signal.Signals(-returncode).name
        return f"CRASH({sig})"
    if returncode == 0:
        return "OK"
    return f"EXIT({returncode})"


def check(fixtures_dir: Path, command: list[str], timeout: float) -> int:
    paths = [p for p in sorted(fixtures_dir.iterdir()) if p.is_file() and p.name != "manifest.json"]
    width = max([len(p.name) for p in paths] + [7])
    worst = 0
    for path in paths:
        argv = command_for(command, path)
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout)
            status = verdict(proc.returncode)
            if proc.returncode and proc.returncode < 0:
                worst = 2
            elif proc.returncode and worst == 0:
                worst = 1
            detail = (proc.stderr or proc.stdout).decode("utf-8", "replace").splitlines()
            msg = detail[0] if detail else ""
        except subprocess.TimeoutExpired:
            status = "TIMEOUT"
            worst = max(worst, 2)
            msg = ""
        except FileNotFoundError as e:
            raise SystemExit(str(e)) from e
        print(f"{path.name:<{width}}  {status:<16} {msg}")
    return worst


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("generate", help="write malformed ELF fixtures")
    gen.add_argument("out_dir", type=Path)

    chk = sub.add_parser("check", help="run fixtures through a loader/tool")
    chk.add_argument("fixtures_dir", type=Path)
    chk.add_argument("--timeout", type=float, default=5.0)
    chk.add_argument("command", nargs=argparse.REMAINDER)

    args = parser.parse_args()
    if args.cmd == "generate":
        generate(args.out_dir)
        return 0
    if args.cmd == "check":
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not command:
            raise SystemExit("check requires a command after --")
        return check(args.fixtures_dir, command, args.timeout)
    raise AssertionError(args.cmd)


if __name__ == "__main__":
    sys.exit(main())
