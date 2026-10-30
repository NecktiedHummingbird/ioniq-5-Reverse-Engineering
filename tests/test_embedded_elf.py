"""Tests for strict, read-only embedded ELF extraction and address mapping."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOL = Path(__file__).parents[1] / "tools" / "uk_fw" / "embedded_elf.py"
SPEC = importlib.util.spec_from_file_location("embedded_elf", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")


def align(value: int, amount: int = 8) -> int:
    return (value + amount - 1) & ~(amount - 1)


def make_elf(sections: list[tuple[str, bytes]], entry_section: str = ".text") -> tuple[bytes, dict[str, int]]:
    """Construct a small but complete ELF64 fixture with one executable LOAD."""
    cursor = 0x100
    offsets: dict[str, int] = {}
    body = bytearray(cursor)
    for name, content in sections:
        cursor = align(cursor)
        if len(body) < cursor:
            body.extend(b"\0" * (cursor - len(body)))
        offsets[name] = cursor
        body.extend(content)
        cursor += len(content)

    names = bytearray(b"\0")
    name_offsets = {}
    for name, _content in sections:
        name_offsets[name] = len(names)
        names.extend(name.encode("ascii") + b"\0")
    name_offsets[".shstrtab"] = len(names)
    names.extend(b".shstrtab\0")
    cursor = align(cursor)
    if len(body) < cursor:
        body.extend(b"\0" * (cursor - len(body)))
    shstr_offset = cursor
    body.extend(names)
    shoff = align(len(body))
    body.extend(b"\0" * (shoff - len(body)))

    section_rows = [SECTION_HEADER.pack(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    for name, content in sections:
        flags = 0x6 if name == ".text" else 0x2
        section_rows.append(SECTION_HEADER.pack(
            name_offsets[name], 1, flags, offsets[name], offsets[name], len(content),
            0, 0, 1, 0,
        ))
    section_rows.append(SECTION_HEADER.pack(
        name_offsets[".shstrtab"], 3, 0, 0, shstr_offset, len(names), 0, 0, 1, 0,
    ))
    for row in section_rows:
        body.extend(row)

    total = len(body)
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\0" * 8
    header = ELF_HEADER.pack(
        ident, 3, 62, 1, offsets[entry_section], ELF_HEADER.size, shoff, 0,
        ELF_HEADER.size, PROGRAM_HEADER.size, 1, SECTION_HEADER.size,
        len(section_rows), len(section_rows) - 1,
    )
    program = PROGRAM_HEADER.pack(1, 5, 0, 0, 0, total, total, 0x1000)
    body[:ELF_HEADER.size] = header
    body[ELF_HEADER.size:ELF_HEADER.size + PROGRAM_HEADER.size] = program
    return bytes(body), offsets


def make_container(*, invalid_magic: bool = False) -> tuple[bytes, dict[str, int | bytes]]:
    first, first_offsets = make_elf([(".text", b"\x90\xc3"), (".rodata", b"first")])
    second, second_offsets = make_elf([(".text", b"\x90\x90\xc3"), (".rodata", b"second")])
    prefix = b"wrapper"
    if invalid_magic:
        prefix += b"\x7fELF\x01invalid"
    rodata = prefix + first + b"\0" * 4 + second + b"\0" * 11
    outer, outer_offsets = make_elf([(".text", b"\x90\xc3"), (".rodata", rodata)])
    first_start = outer_offsets[".rodata"] + len(prefix)
    second_start = first_start + len(first) + 4
    return outer, {
        "first": first_start,
        "second": second_start,
        "first_bytes": first,
        "second_bytes": second,
        "first_text": first_offsets[".text"],
        "second_text": second_offsets[".text"],
        "outer_rodata_end": outer_offsets[".rodata"] + len(rodata),
    }


class EmbeddedElfTests(unittest.TestCase):
    def test_finds_sibling_images_and_separates_padding(self) -> None:
        data, expected = make_container(invalid_magic=True)
        images, rejected = MODULE.find_elf_images(data)
        self.assertEqual([image.outer_offset for image in images],
                         [0, expected["first"], expected["second"]])
        self.assertEqual(images[1].structural_extent, len(expected["first_bytes"]))
        self.assertEqual(images[1].gap_after_extent, 4)
        self.assertEqual(images[2].structural_extent, len(expected["second_bytes"]))
        self.assertEqual(images[2].container_end, expected["outer_rodata_end"])
        self.assertEqual(images[2].gap_after_extent, 11)
        self.assertEqual(len(rejected), 1)
        self.assertIn("64-bit", rejected[0]["reason"])

    def test_virtual_address_mapping_names_all_three_spaces(self) -> None:
        data, expected = make_container()
        images, _rejected = MODULE.find_elf_images(data)
        first = images[1]
        address = int(expected["first_text"])
        self.assertEqual(first.vaddr_to_file_offset(address), address)
        self.assertEqual(first.outer_offset + address,
                         int(expected["first"]) + address)
        self.assertEqual(first.file_offset_to_vaddr(address), address)
        self.assertIsNone(first.vaddr_to_file_offset(first.structural_extent + 1))

    def test_extracts_only_structural_extents_and_refuses_overwrite(self) -> None:
        data, expected = make_container()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "AppUpgrade"
            source.write_bytes(data)
            report, loaded, images = MODULE.inspect(source)
            output = root / "out"
            extracted = MODULE.extract_images(source, output, loaded, images)
            first_out = Path(extracted[0]["path"])
            second_out = Path(extracted[1]["path"])
            self.assertEqual(first_out.read_bytes(), expected["first_bytes"])
            self.assertEqual(second_out.read_bytes(), expected["second_bytes"])
            self.assertEqual(report["schema"], "ioniq5-embedded-elf-v2")
            self.assertIn("gap_after_structural_extent", report["images"][1])
            self.assertNotIn("container_padding", report["images"][1])
            with self.assertRaisesRegex(MODULE.EmbeddedElfError, "overwrite"):
                MODULE.extract_images(source, output, loaded, images)

    def test_truncated_tables_fail_closed(self) -> None:
        image, _offsets = make_elf([(".text", b"\x90\xc3")])
        with self.assertRaisesRegex(MODULE.EmbeddedElfError, "outside"):
            MODULE.parse_elf_at(image[:-20], 0)

    def test_nested_structural_overlap_fails_closed(self) -> None:
        nested, _nested_offsets = make_elf([(".text", b"\x90\xc3")])
        parent, _parent_offsets = make_elf([
            (".text", b"\x90\xc3"),
            (".payload", b"prefix" + nested + b"suffix"),
        ])
        outer, _outer_offsets = make_elf([
            (".text", b"\x90\xc3"),
            (".rodata", parent),
        ])
        with self.assertRaisesRegex(MODULE.EmbeddedElfError, "overlaps"):
            MODULE.find_elf_images(outer)

    def test_embedded_image_must_be_inside_one_outer_section(self) -> None:
        outer, _offsets = make_elf([(".text", b"\x90\xc3")])
        appended, _appended_offsets = make_elf([(".text", b"\x90\xc3")])
        with self.assertRaisesRegex(MODULE.EmbeddedElfError, "not uniquely contained"):
            MODULE.find_elf_images(outer + appended)

    def test_ambiguous_load_mappings_fail_closed(self) -> None:
        image, _offsets = make_elf([(".text", b"\x90\xc3")])
        body = bytearray(image)
        values = list(ELF_HEADER.unpack_from(body, 0))
        values[10] = 2  # e_phnum
        body[:ELF_HEADER.size] = ELF_HEADER.pack(*values)
        second = PROGRAM_HEADER.pack(1, 5, 1, 0, 0, len(body) - 1,
                                     len(body) - 1, 1)
        body[ELF_HEADER.size + PROGRAM_HEADER.size:
             ELF_HEADER.size + 2 * PROGRAM_HEADER.size] = second
        with self.assertRaisesRegex(MODULE.EmbeddedElfError, "ambiguous"):
            MODULE.parse_elf_at(bytes(body), 0)

    def test_nonidentity_mapping_and_memory_only_tail(self) -> None:
        image, offsets = make_elf([(".text", b"\x90\xc3")])
        body = bytearray(image)
        values = list(ELF_HEADER.unpack_from(body, 0))
        delta = 0x200000
        values[4] += delta  # e_entry
        body[:ELF_HEADER.size] = ELF_HEADER.pack(*values)
        program = list(PROGRAM_HEADER.unpack_from(body, ELF_HEADER.size))
        program[3] += delta  # p_vaddr
        program[4] += delta  # p_paddr
        program[6] += 0x100  # p_memsz, creating a memory-only tail
        body[ELF_HEADER.size:ELF_HEADER.size + PROGRAM_HEADER.size] = (
            PROGRAM_HEADER.pack(*program)
        )
        shoff = values[6]
        shnum = values[12]
        for index in range(shnum):
            start = shoff + index * SECTION_HEADER.size
            section = list(SECTION_HEADER.unpack_from(body, start))
            if section[3]:
                section[3] += delta
                body[start:start + SECTION_HEADER.size] = SECTION_HEADER.pack(*section)
        parsed = MODULE.parse_elf_at(bytes(body), 0)
        text_address = delta + offsets[".text"]
        self.assertEqual(parsed.vaddr_to_file_offset(text_address), offsets[".text"])
        self.assertEqual(parsed.file_offset_to_vaddr(offsets[".text"]), text_address)
        self.assertIsNone(parsed.vaddr_to_file_offset(delta + len(body) + 1))

    def test_write_failure_removes_partial_outputs(self) -> None:
        data, _expected = make_container()

        class FailingOutput:
            def __init__(self, descriptor: int) -> None:
                self.descriptor = descriptor

            def __enter__(self) -> "FailingOutput":
                return self

            def write(self, _payload: bytes) -> None:
                raise OSError("synthetic write failure")

            def __exit__(self, *_args: object) -> None:
                os.close(self.descriptor)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "AppUpgrade"
            source.write_bytes(data)
            _report, loaded, images = MODULE.inspect(source)
            output = root / "out"
            with mock.patch.object(MODULE.os, "fdopen",
                                   side_effect=lambda fd, _mode: FailingOutput(fd)):
                with self.assertRaisesRegex(MODULE.EmbeddedElfError, "write failure"):
                    MODULE.extract_images(source, output, loaded, images)
            self.assertEqual(list(output.iterdir()), [])

    def test_invalid_mapping_is_checked_before_extraction(self) -> None:
        data, _expected = make_container()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "AppUpgrade"
            source.write_bytes(data)
            output = root / "out"
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                result = MODULE.main([
                    str(source), "--extract-dir", str(output),
                    "--map-vaddr", "0xdead:0x100",
                ])
            self.assertEqual(result, 2)
            self.assertFalse(output.exists())

    def test_symlink_extraction_directory_is_rejected(self) -> None:
        data, _expected = make_container()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "AppUpgrade"
            source.write_bytes(data)
            _report, loaded, images = MODULE.inspect(source)
            real = root / "real"
            real.mkdir()
            link = root / "out"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(MODULE.EmbeddedElfError, "real directory"):
                MODULE.extract_images(source, link, loaded, images)


if __name__ == "__main__":
    unittest.main()
