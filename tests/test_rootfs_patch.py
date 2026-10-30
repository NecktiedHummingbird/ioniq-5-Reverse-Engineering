"""Tests for the rootfs repacker."""

from __future__ import annotations

import gzip
import importlib.util
import io
import tarfile
import tempfile
import unittest
import zlib
from pathlib import Path

TOOL = Path(__file__).parents[1] / "tools" / "uk_fw" / "rootfs_patch.py"
SPEC = importlib.util.spec_from_file_location("rootfs_patch", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def make_package(path: Path, files: dict) -> None:
    with tarfile.open(path, "w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo("./" + name)
            info.size = len(data)
            info.mode = 0o644
            info.uid = info.gid = 0
            tf.addfile(info, io.BytesIO(data))


def members(path: Path):
    with tarfile.open(path, "r:gz") as tf:
        return sorted(m.name for m in tf.getmembers())


class RootfsPatchTests(unittest.TestCase):
    def test_list_counts_members(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            pkg = Path(temp) / "rootfs.tar.gz"
            make_package(pkg, {"etc/hostname": b"hu", "app/a.txt": b"x"})
            result = MODULE.list_package(pkg, 10)
        self.assertEqual(result["members"], 2)

    def test_inject_adds_file_and_preserves_original(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pkg = root / "rootfs.tar.gz"
            make_package(pkg, {"etc/hostname": b"hu"})
            src = root / "payload.bin"
            src.write_bytes(b"\x00\x01\x02")
            out = root / "out" / "rootfs.tar.gz"
            result = MODULE.inject(pkg, out, [f"{src}:opt/payload.bin"], None, None, None, None)
            names = members(out)
            size = out.stat().st_size
        self.assertIn("./opt/payload.bin", names)
        self.assertIn("./etc/hostname", names)
        self.assertEqual(result["size"], size)

    def test_ssh_key_is_appended_with_mode_600(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pkg = root / "rootfs.tar.gz"
            make_package(pkg, {MODULE.DROPBEAR_KEYS: b"ssh-ed25519 OLD\n"})
            key = root / "id.pub"
            key.write_bytes(b"ssh-ed25519 NEW bench\n")
            out = root / "o.tar.gz"
            MODULE.inject(pkg, out, [], None, None, key, None)
            with tarfile.open(out, "r:gz") as tf:
                data = tf.extractfile("./" + MODULE.DROPBEAR_KEYS).read()
                mode = tf.getmember("./" + MODULE.DROPBEAR_KEYS).mode
        self.assertIn(b"OLD", data)
        self.assertIn(b"NEW bench", data)
        self.assertEqual(mode, 0o600)

    def test_meta_updates_manifest_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            rebuilt = root / "mango-rootfs.tar.gz"
            rebuilt.write_bytes(b"payload-bytes")
            manifest = root / "x.ver"
            manifest.write_text(
                "+|1|V|HM|IONIQ5_EU|101489|1\n"
                "IONIQ5_EU\\HU\\images|mango-rootfs.tar.gz|341174|0|13|1\n"
                "IONIQ5_EU\\AppUpgrade|AppUpgrade|341142|0|5|1\n"
            )
            written = root / "out.ver"
            result = MODULE.update_manifest(manifest, rebuilt, written, "mango-rootfs.tar.gz")
            text = written.read_text()
        crc = zlib.crc32(b"payload-bytes") & 0xFFFFFFFF
        signed = crc - (1 << 32) if crc & 0x80000000 else crc
        self.assertEqual(result["records_updated"], 1)
        self.assertIn(f"|{signed}|13|1", text)
        self.assertIn("|0|5|1", text)  # unrelated record untouched

    def test_rejects_archive_parent_traversal_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "traversal.tar.gz"
            with tarfile.open(package, "w:gz") as tf:
                info = tarfile.TarInfo("../escape")
                info.size = 1
                tf.addfile(info, io.BytesIO(b"x"))
            with self.assertRaisesRegex(MODULE.ArchiveSafetyError, "traversal"):
                MODULE.inject(package, root / "out.tar.gz", [], None, None, None, None)
            self.assertFalse((root / "escape").exists())

    def test_rejects_links_and_special_members(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "link.tar.gz"
            with tarfile.open(package, "w:gz") as tf:
                info = tarfile.TarInfo("./etc/outside")
                info.type = tarfile.SYMTYPE
                info.linkname = "../../outside"
                tf.addfile(info)
            with self.assertRaisesRegex(MODULE.ArchiveSafetyError, "links and special"):
                MODULE.inject(package, root / "out.tar.gz", [], None, None, None, None)

    def test_rejects_escaping_injection_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "rootfs.tar.gz"
            make_package(package, {"etc/hostname": b"hu"})
            payload = root / "payload"
            payload.write_bytes(b"x")
            with self.assertRaisesRegex(MODULE.ArchiveSafetyError, "traversal"):
                MODULE.inject(
                    package,
                    root / "out.tar.gz",
                    [f"{payload}:opt/app/../../../escape"],
                    None,
                    None,
                    None,
                    None,
                )
            self.assertFalse((root / "escape").exists())

    def test_refuses_in_place_package_or_manifest_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "rootfs.tar.gz"
            make_package(package, {"etc/hostname": b"hu"})
            with self.assertRaisesRegex(MODULE.ArchiveSafetyError, "must not overwrite"):
                MODULE.inject(package, package, [], None, None, None, None)
            existing_output = root / "existing.tar.gz"
            existing_output.write_bytes(b"keep")
            with self.assertRaisesRegex(MODULE.ArchiveSafetyError, "already exists"):
                MODULE.inject(package, existing_output, [], None, None, None, None)
            self.assertEqual(existing_output.read_bytes(), b"keep")

            manifest = root / "x.ver"
            manifest.write_text("+|1|V|HM|IONIQ5_EU|1|1\n")
            with self.assertRaisesRegex(MODULE.ArchiveSafetyError, "must not overwrite"):
                MODULE.update_manifest(manifest, package, manifest, "rootfs.tar.gz")

    def test_refuses_hard_link_alias_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "rootfs.tar.gz"
            make_package(package, {"etc/hostname": b"hu"})
            original = package.read_bytes()
            package_alias = root / "package-alias.tar.gz"
            package_alias.hardlink_to(package)
            with self.assertRaisesRegex(MODULE.ArchiveSafetyError, "must not overwrite"):
                MODULE.inject(package, package_alias, [], None, None, None, None)
            self.assertEqual(package.read_bytes(), original)

            manifest = root / "x.ver"
            manifest.write_text("+|1|V|HM|IONIQ5_EU|1|1\n")
            manifest_alias = root / "manifest-alias.ver"
            manifest_alias.hardlink_to(manifest)
            with self.assertRaisesRegex(MODULE.ArchiveSafetyError, "must not overwrite"):
                MODULE.update_manifest(manifest, package, manifest_alias, "rootfs.tar.gz")

            rebuilt_alias = root / "rebuilt-alias.ver"
            rebuilt_alias.hardlink_to(package)
            with self.assertRaisesRegex(MODULE.ArchiveSafetyError, "rebuilt package"):
                MODULE.update_manifest(manifest, package, rebuilt_alias, "rootfs.tar.gz")
            self.assertEqual(package.read_bytes(), original)

    def test_rejects_duplicate_directory_members(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "duplicate-dir.tar.gz"
            with tarfile.open(package, "w:gz") as tf:
                first = tarfile.TarInfo("./etc")
                first.type = tarfile.DIRTYPE
                first.mode = 0o755
                tf.addfile(first)
                second = tarfile.TarInfo("./etc")
                second.type = tarfile.DIRTYPE
                second.mode = 0o700
                tf.addfile(second)
            with self.assertRaisesRegex(MODULE.ArchiveSafetyError, "duplicate"):
                MODULE.inject(package, root / "out.tar.gz", [], None, None, None, None)

    def test_top_level_dotfile_name_survives_repack(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "dotfile.tar.gz"
            make_package(package, {".vendor": b"hidden"})
            output = root / "out.tar.gz"
            MODULE.inject(package, output, [], None, None, None, None)
            with tarfile.open(output, "r:gz") as tf:
                self.assertIn("./.vendor", tf.getnames())
                self.assertNotIn("./vendor", tf.getnames())
                self.assertEqual(tf.extractfile("./.vendor").read(), b"hidden")

    def test_read_only_directory_and_numeric_metadata_survive_repack(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "readonly.tar.gz"
            with tarfile.open(package, "w:gz") as tf:
                directory = tarfile.TarInfo("./readonly")
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o555
                directory.uid = 42
                directory.gid = 43
                directory.mtime = 123
                tf.addfile(directory)
                child = tarfile.TarInfo("./readonly/file")
                child.size = 1
                child.mode = 0o400
                child.uid = 44
                child.gid = 45
                child.mtime = 456
                tf.addfile(child, io.BytesIO(b"x"))
            output = root / "out.tar.gz"
            MODULE.inject(package, output, [], None, None, None, None)
            with gzip.open(output, "rb") as compressed:
                raw_tar = compressed.read()
            self.assertEqual(raw_tar[257:263], b"ustar\x00")
            with tarfile.open(output, "r:gz") as tf:
                out_dir = tf.getmember("./readonly")
                out_file = tf.getmember("./readonly/file")
                self.assertEqual((out_dir.mode, out_dir.uid, out_dir.gid, out_dir.mtime),
                                 (0o555, 42, 43, 123))
                self.assertEqual((out_file.mode, out_file.uid, out_file.gid, out_file.mtime),
                                 (0o400, 44, 45, 456))
                self.assertEqual(tf.extractfile(out_file).read(), b"x")


if __name__ == "__main__":
    unittest.main()
