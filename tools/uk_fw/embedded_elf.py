#!/usr/bin/env python3
"""Inspect and extract ELF64 files embedded in another ELF without executing them.

The updater recovered from Gen5W firmware is an outer ELF whose read-only data
contains complete updater executables.  This tool keeps three address spaces
explicit:

* outer file offsets;
* an embedded ELF's file offsets; and
* that ELF's virtual addresses.

Extraction stops at the embedded ELF's structural file extent. Bytes between
that extent and a containing-section/sibling boundary, including resource
metadata and a following embedded ELF, are never copied into the output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

ELF_MAGIC = b"\x7fELF"
ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
NOTE_HEADER = struct.Struct("<III")

ET_EXEC = 2
ET_DYN = 3
PT_LOAD = 1
PF_X = 1
SHT_NOBITS = 8
SHT_NOTE = 7
SHF_ALLOC = 2


class EmbeddedElfError(ValueError):
    """The container or an explicitly selected embedded ELF is invalid."""


@dataclass(frozen=True)
class ProgramHeader:
    type: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int
    align: int


@dataclass(frozen=True)
class SectionHeader:
    index: int
    name_offset: int
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int


@dataclass
class ElfImage:
    outer_offset: int
    elf_type: int
    machine: int
    entry: int
    program_headers: list[ProgramHeader]
    sections: list[SectionHeader]
    structural_extent: int
    build_id: Optional[str]
    container_end: Optional[int] = None

    @property
    def structural_end(self) -> int:
        return self.outer_offset + self.structural_extent

    @property
    def boundary_span(self) -> Optional[int]:
        if self.container_end is None:
            return None
        return self.container_end - self.outer_offset

    @property
    def gap_after_extent(self) -> Optional[int]:
        if self.container_end is None:
            return None
        return self.container_end - self.structural_end

    def vaddr_to_file_offset(self, address: int) -> Optional[int]:
        """Map a virtual address only when its bytes exist in the file."""
        for segment in self.program_headers:
            if segment.type != PT_LOAD:
                continue
            if segment.vaddr <= address < segment.vaddr + segment.filesz:
                return segment.offset + (address - segment.vaddr)
        return None

    def file_offset_to_vaddr(self, offset: int) -> Optional[int]:
        for segment in self.program_headers:
            if segment.type != PT_LOAD:
                continue
            if segment.offset <= offset < segment.offset + segment.filesz:
                return segment.vaddr + (offset - segment.offset)
        return None

    def to_dict(self, *, top_level: bool) -> dict:
        entry_file = self.vaddr_to_file_offset(self.entry)
        selected_sections = {}
        for section in self.sections:
            if section.name in {".text", ".rodata", ".data", ".bss"}:
                selected_sections[section.name] = {
                    "virtual_address": section.addr,
                    "file_offset": section.offset,
                    "size": section.size,
                    "file_backed": section.type != SHT_NOBITS,
                }
        return {
            "kind": "outer" if top_level else "embedded",
            "outer_file_offset": self.outer_offset,
            "elf_type": self.elf_type,
            "machine": self.machine,
            "entry_virtual_address": self.entry,
            "entry_file_offset": entry_file,
            "entry_outer_file_offset": (
                None if entry_file is None else self.outer_offset + entry_file
            ),
            "build_id": self.build_id,
            "structural_file_extent": self.structural_extent,
            "structural_outer_end": self.structural_end,
            "boundary_span": self.boundary_span,
            "boundary_outer_end": self.container_end,
            "gap_after_structural_extent": self.gap_after_extent,
            "sections": selected_sections,
        }


def _checked_end(start: int, size: int, limit: int, what: str) -> int:
    if start < 0 or size < 0 or start > limit or size > limit - start:
        raise EmbeddedElfError(f"{what} is outside the container")
    return start + size


def _read_c_string(data: bytes, start: int, limit: int) -> str:
    if start < 0 or start >= limit:
        raise EmbeddedElfError("section-name offset is outside the string table")
    end = data.find(b"\0", start, limit)
    if end < 0:
        raise EmbeddedElfError("unterminated section name")
    return data[start:end].decode("latin-1")


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _gnu_build_id(data: bytes, base: int, sections: Iterable[SectionHeader]) -> Optional[str]:
    for section in sections:
        if section.type != SHT_NOTE or section.size < NOTE_HEADER.size:
            continue
        cursor = base + section.offset
        end = cursor + section.size
        while cursor + NOTE_HEADER.size <= end:
            namesz, descsz, note_type = NOTE_HEADER.unpack_from(data, cursor)
            cursor += NOTE_HEADER.size
            name_end = cursor + namesz
            desc_start = cursor + _align4(namesz)
            desc_end = desc_start + descsz
            next_note = desc_start + _align4(descsz)
            if name_end > end or desc_end > end or next_note > end:
                break
            name = data[cursor:name_end].rstrip(b"\0")
            if name == b"GNU" and note_type == 3:
                return data[desc_start:desc_end].hex()
            cursor = next_note
    return None


def parse_elf_at(data: bytes, outer_offset: int) -> ElfImage:
    """Parse one strict ELF64 little-endian image at *outer_offset*."""
    _checked_end(outer_offset, ELF_HEADER.size, len(data), "ELF header")
    values = ELF_HEADER.unpack_from(data, outer_offset)
    ident = values[0]
    if ident[:4] != ELF_MAGIC:
        raise EmbeddedElfError("missing ELF magic")
    if ident[4] != 2:
        raise EmbeddedElfError("ELF is not 64-bit")
    if ident[5] != 1:
        raise EmbeddedElfError("ELF is not little-endian")
    if ident[6] != 1:
        raise EmbeddedElfError("unsupported ELF identification version")

    (
        _ident,
        elf_type,
        machine,
        version,
        entry,
        phoff,
        shoff,
        _flags,
        ehsize,
        phentsize,
        phnum,
        shentsize,
        shnum,
        shstrndx,
    ) = values
    if elf_type not in {ET_EXEC, ET_DYN}:
        raise EmbeddedElfError("ELF is not executable or shared-object type")
    if version != 1 or ehsize != ELF_HEADER.size:
        raise EmbeddedElfError("unsupported ELF header version or size")
    if phnum == 0 or phnum == 0xFFFF:
        raise EmbeddedElfError("ELF has no ordinary program-header table")
    if phentsize != PROGRAM_HEADER.size:
        raise EmbeddedElfError("unexpected program-header size")
    if shnum == 0 or shstrndx == 0xFFFF:
        raise EmbeddedElfError("extended or absent section tables are unsupported")
    if shentsize != SECTION_HEADER.size or shstrndx >= shnum:
        raise EmbeddedElfError("invalid section-header table")

    relative_limit = len(data) - outer_offset
    ph_table_end = _checked_end(phoff, phnum * phentsize, relative_limit,
                                "program-header table")
    sh_table_end = _checked_end(shoff, shnum * shentsize, relative_limit,
                                "section-header table")

    programs: list[ProgramHeader] = []
    extent = max(ehsize, ph_table_end, sh_table_end)
    uint64_limit = 1 << 64
    for index in range(phnum):
        raw = PROGRAM_HEADER.unpack_from(data, outer_offset + phoff + index * phentsize)
        p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_align = raw
        if p_filesz:
            p_end = _checked_end(p_offset, p_filesz, relative_limit,
                                 f"program header {index}")
            extent = max(extent, p_end)
        if p_memsz < p_filesz:
            raise EmbeddedElfError(f"program header {index} has memsz < filesz")
        if p_vaddr > uint64_limit - p_memsz:
            raise EmbeddedElfError(f"program header {index} virtual range overflows")
        if p_align not in {0, 1}:
            if p_align & (p_align - 1):
                raise EmbeddedElfError(f"program header {index} has invalid alignment")
            if p_offset % p_align != p_vaddr % p_align:
                raise EmbeddedElfError(f"program header {index} is not congruent")
        programs.append(ProgramHeader(p_type, p_flags, p_offset, p_vaddr,
                                      p_filesz, p_memsz, p_align))

    raw_sections = []
    for index in range(shnum):
        raw = SECTION_HEADER.unpack_from(data, outer_offset + shoff + index * shentsize)
        raw_sections.append(raw)
        _name, section_type, _flags, _addr, section_offset, section_size = raw[:6]
        if section_type != SHT_NOBITS and section_size:
            section_end = _checked_end(section_offset, section_size, relative_limit,
                                       f"section {index}")
            extent = max(extent, section_end)

    shstr_raw = raw_sections[shstrndx]
    if shstr_raw[1] == SHT_NOBITS:
        raise EmbeddedElfError("section-name table is not file-backed")
    shstr_start = outer_offset + shstr_raw[4]
    shstr_end = shstr_start + shstr_raw[5]
    sections: list[SectionHeader] = []
    for index, raw in enumerate(raw_sections):
        name_offset, section_type, flags, addr, section_offset, section_size = raw[:6]
        name = _read_c_string(data, shstr_start + name_offset, shstr_end)
        sections.append(SectionHeader(index, name_offset, name, section_type,
                                      flags, addr, section_offset, section_size))

    load_segments = [segment for segment in programs if segment.type == PT_LOAD]
    if not load_segments:
        raise EmbeddedElfError("ELF has no loadable segment")
    file_backed_loads = [segment for segment in load_segments if segment.filesz]
    for left_index, left in enumerate(file_backed_loads):
        for right in file_backed_loads[left_index + 1:]:
            virtual_overlap = (
                max(left.vaddr, right.vaddr)
                < min(left.vaddr + left.filesz, right.vaddr + right.filesz)
            )
            file_overlap = (
                max(left.offset, right.offset)
                < min(left.offset + left.filesz, right.offset + right.filesz)
            )
            left_delta = left.offset - left.vaddr
            right_delta = right.offset - right.vaddr
            if (virtual_overlap or file_overlap) and left_delta != right_delta:
                raise EmbeddedElfError("ambiguous overlapping PT_LOAD mappings")
    entry_segment = next((segment for segment in load_segments
                          if segment.flags & PF_X
                          and segment.vaddr <= entry < segment.vaddr + segment.filesz), None)
    if entry_segment is None:
        raise EmbeddedElfError("entry point is not in a file-backed executable segment")

    return ElfImage(
        outer_offset=outer_offset,
        elf_type=elf_type,
        machine=machine,
        entry=entry,
        program_headers=programs,
        sections=sections,
        structural_extent=extent,
        build_id=_gnu_build_id(data, outer_offset, sections),
    )


def find_elf_images(data: bytes) -> tuple[list[ElfImage], list[dict]]:
    """Return strict ELF images plus rejected magic offsets and reasons."""
    images: list[ElfImage] = []
    rejected: list[dict] = []
    cursor = 0
    while True:
        offset = data.find(ELF_MAGIC, cursor)
        if offset < 0:
            break
        try:
            images.append(parse_elf_at(data, offset))
        except (EmbeddedElfError, struct.error) as error:
            rejected.append({"outer_file_offset": offset, "reason": str(error)})
        cursor = offset + 1
    images.sort(key=lambda image: image.outer_offset)
    if not images or images[0].outer_offset != 0:
        raise EmbeddedElfError("container does not begin with a valid ELF")

    outer = images[0]
    outer_sections = [section for section in outer.sections
                      if section.type != SHT_NOBITS and section.size]
    embedded = images[1:]
    for index, image in enumerate(embedded):
        containing = [
            section for section in outer_sections
            if section.offset <= image.outer_offset
            and image.structural_end <= section.offset + section.size
        ]
        if len(containing) != 1:
            raise EmbeddedElfError(
                f"embedded ELF at 0x{image.outer_offset:x} is not uniquely "
                "contained in one outer file-backed section"
            )
        section_end = containing[0].offset + containing[0].size
        next_start = (embedded[index + 1].outer_offset
                      if index + 1 < len(embedded) else section_end)
        boundary = min(section_end, next_start)
        if image.structural_end > boundary:
            raise EmbeddedElfError(
                f"embedded ELF at 0x{image.outer_offset:x} overlaps its boundary"
            )
        image.container_end = boundary
    outer.container_end = len(data)
    return images, rejected


def inspect(path: Path) -> tuple[dict, bytes, list[ElfImage]]:
    data = path.read_bytes()
    images, rejected = find_elf_images(data)
    report = {
        "schema": "ioniq5-embedded-elf-v2",
        "input": str(path),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "images": [image.to_dict(top_level=index == 0)
                   for index, image in enumerate(images)],
        "rejected_elf_magic": rejected,
    }
    return report, data, images


def _prepare_output_directory(output_dir: Path) -> int:
    """Create and pin a final directory that is not itself a symlink."""
    output_dir.mkdir(parents=True, exist_ok=True)
    if output_dir.is_symlink() or not output_dir.is_dir():
        raise EmbeddedElfError("extraction destination must be a real directory")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(output_dir, flags)
    except OSError as error:
        raise EmbeddedElfError(f"could not open extraction directory: {error}") from error


def extract_images(input_path: Path, output_dir: Path, data: bytes,
                   images: list[ElfImage]) -> list[dict]:
    directory_fd = _prepare_output_directory(output_dir)
    planned: list[tuple[ElfImage, str, Path]] = []
    try:
        for image in images[1:]:
            name = f"{input_path.name}.embedded-{image.outer_offset:x}.elf"
            output = output_dir / name
            try:
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise EmbeddedElfError(f"refusing to overwrite {output}")
            planned.append((image, name, output))

        written = []
        created: list[str] = []
        try:
            for image, name, output in planned:
                payload = data[image.outer_offset:image.structural_end]
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                flags |= getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(name, flags, 0o666, dir_fd=directory_fd)
                created.append(name)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payload)
                written.append({
                    "outer_file_offset": image.outer_offset,
                    "path": str(output),
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                })
        except (FileExistsError, OSError) as error:
            for name in created:
                try:
                    os.unlink(name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
            raise EmbeddedElfError(
                f"could not create extraction outputs: {error}"
            ) from error
        return written
    finally:
        os.close(directory_fd)


def _integer(value: str) -> int:
    try:
        result = int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid integer: {value}") from error
    if result < 0:
        raise argparse.ArgumentTypeError("offsets and addresses must be non-negative")
    return result


def _map_request(value: str) -> tuple[int, int]:
    try:
        image_offset, address = value.split(":", 1)
    except ValueError as error:
        raise argparse.ArgumentTypeError("mapping must be ELF_OFFSET:VADDR") from error
    return _integer(image_offset), _integer(address)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--extract-dir", type=Path,
                        help="write exact structural extents for embedded ELFs")
    parser.add_argument("--map-vaddr", action="append", default=[], type=_map_request,
                        metavar="ELF_OFFSET:VADDR",
                        help="map an embedded virtual address to file/outer offsets")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    args = parser.parse_args(argv)

    try:
        report, data, images = inspect(args.input)
        by_offset = {image.outer_offset: image for image in images}
        mappings = []
        for image_offset, address in args.map_vaddr:
            image = by_offset.get(image_offset)
            if image is None:
                raise EmbeddedElfError(f"no ELF begins at 0x{image_offset:x}")
            file_offset = image.vaddr_to_file_offset(address)
            mappings.append({
                "elf_outer_file_offset": image_offset,
                "virtual_address": address,
                "elf_file_offset": file_offset,
                "outer_file_offset": (
                    None if file_offset is None else image_offset + file_offset
                ),
            })
        if mappings:
            report["mappings"] = mappings
        if args.extract_dir is not None:
            report["extracted"] = extract_images(args.input, args.extract_dir, data, images)
    except (OSError, EmbeddedElfError) as error:
        print(f"embedded_elf: {error}", file=sys.stderr)
        return 2

    json.dump(report, sys.stdout, indent=2 if args.pretty else None, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
