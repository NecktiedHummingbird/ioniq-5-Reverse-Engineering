"""Tests for the read-only extracted-root privilege-surface analyzer."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

TOOL = Path(__file__).parents[1] / "tools/uk_fw/privilege_surface.py"
SPEC = importlib.util.spec_from_file_location("privilege_surface", TOOL)
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class TreeFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "rootfs"
        self.root.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def make(self, relative: str, data: str = "", mode: int = 0o644) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding="utf-8")
        path.chmod(mode)
        return path


class SafetyTests(TreeFixture):
    def test_rejects_symlink_root_and_output_inside_tree(self):
        link = Path(self.temp.name) / "root-link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(AUDIT.AuditError, "symlink"):
            AUDIT.validate_root(link)
        with self.assertRaisesRegex(AUDIT.AuditError, "outside"):
            AUDIT.validate_output(self.root / "report.json", self.root.resolve())

    def test_existing_hardlink_output_is_replaced_without_touching_root(self):
        protected = self.make("etc/protected", "original\n")
        output = Path(self.temp.name) / "report.json"
        os.link(protected, output)
        validated = AUDIT.validate_output(output, self.root.resolve())
        AUDIT.write_output_atomic(validated, '{"safe": true}\n')
        self.assertEqual(protected.read_text(encoding="utf-8"), "original\n")
        self.assertEqual(output.read_text(encoding="utf-8"), '{"safe": true}\n')
        self.assertNotEqual(protected.stat().st_ino, output.stat().st_ino)

    def test_walk_never_follows_directory_or_file_symlinks(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (outside / "secret").write_text("not visited", encoding="utf-8")
        (self.root / "jump").symlink_to(outside, target_is_directory=True)
        target = self.make("bin/tool", "x", 0o755)
        (self.root / "tool-link").symlink_to(target)
        paths, warnings = AUDIT.walk_no_symlinks(self.root.resolve())
        names = [AUDIT.rel_name(path, self.root.resolve()) for path in paths]
        self.assertIn("/bin/tool", names)
        self.assertNotIn("/jump", names)
        self.assertNotIn("/jump/secret", names)
        self.assertNotIn("/tool-link", names)
        self.assertEqual(warnings, [])


    def test_referenced_loader_path_does_not_cross_intermediate_symlink(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (outside / "host.conf").write_text("/host/secret\n", encoding="utf-8")
        etc = self.root / "etc"
        etc.mkdir()
        self.make("etc/ld.so.conf", "include /etc/ld.so.conf.d/*.conf\n")
        (etc / "ld.so.conf.d").symlink_to(outside, target_is_directory=True)
        loader, _ = AUDIT.loader_inventory(self.root.resolve())
        self.assertNotIn("/host/secret", [item["value"] for item in loader["search_paths"]])


class ModeAndDeterminismTests(TreeFixture):
    def test_setid_and_writable_executable_and_directory(self):
        setid = self.make("usr/bin/setid", "x", 0o4755)
        writable = self.make("opt/runme", "x", 0o777)
        directory = self.root / "opt/drop"
        directory.mkdir(parents=True)
        directory.chmod(0o777)
        report = AUDIT.audit(self.root)
        self.assertEqual(report["findings"]["setid_files"][0]["path"], "/usr/bin/setid")
        self.assertTrue(report["findings"]["setid_files"][0]["setuid"])
        self.assertIn("/opt/runme", [x["path"] for x in report["findings"]["group_or_world_writable_executables"]])
        self.assertIn("/opt/drop", [x["path"] for x in report["findings"]["group_or_world_writable_directories"]])
        self.assertTrue(setid.exists() and writable.exists())

    def test_json_is_deterministic_for_same_tree(self):
        self.make("z/file", "z", 0o755)
        self.make("a/file", "a", 0o755)
        first = json.dumps(AUDIT.audit(self.root), sort_keys=True)
        second = json.dumps(AUDIT.audit(self.root), sort_keys=True)
        self.assertEqual(first, second)


class ServiceTests(TreeFixture):
    def test_default_root_user_override_and_path_evidence(self):
        root_exec = self.make("opt/root-helper", "#!/bin/sh\n", 0o775)
        env = self.make("etc/default/root-service", "LD_LIBRARY_PATH=/opt/writable-lib\n", 0o666)
        libdir = self.root / "opt/writable-lib"
        libdir.mkdir(parents=True)
        libdir.chmod(0o777)
        self.make(
            "lib/systemd/system/root.service",
            """[Service]
ExecStart=-/opt/root-helper --serve
EnvironmentFile=-/etc/default/root-service
""",
        )
        self.make(
            "lib/systemd/system/user.service",
            """[Service]
User=media
Group=audio
ExecStart=/usr/bin/media
""",
        )
        self.make("usr/bin/media", "x", 0o755)
        paths, _ = AUDIT.walk_no_symlinks(self.root.resolve())
        services, warnings = AUDIT.service_inventory(self.root.resolve(), paths)
        self.assertEqual(warnings, [])
        by_name = {item["path"]: item for item in services}
        root_service = by_name["/lib/systemd/system/root.service"]
        self.assertTrue(root_service["effective_default_root"])
        self.assertEqual(root_service["exec"][0]["path_info"]["mode"], "0775")
        self.assertTrue(root_service["environment_files"][0]["path_info"]["world_writable"])
        self.assertEqual(root_service["absolute_loader_environment"][0]["value"], "/opt/writable-lib")
        self.assertFalse(by_name["/lib/systemd/system/user.service"]["effective_default_root"])
        self.assertEqual(by_name["/lib/systemd/system/user.service"]["user"], "media")
        self.assertTrue(root_exec.exists() and env.exists())

    def test_environment_files_override_unit_environment_and_split_preload(self):
        self.make(
            "etc/default/override",
            "LD_LIBRARY_PATH=/from-file\nLD_PRELOAD=/a.so:/b.so /c.so\n",
        )
        self.make(
            "lib/systemd/system/override.service",
            """[Service]
Environment=LD_LIBRARY_PATH=/from-unit LD_PRELOAD=/old.so
EnvironmentFile=/etc/default/override
ExecStart=/bin/true
""",
        )
        paths, _ = AUDIT.walk_no_symlinks(self.root.resolve())
        services, warnings = AUDIT.service_inventory(self.root.resolve(), paths)
        self.assertEqual(warnings, [])
        service = services[0]
        self.assertEqual(
            [item["value"] for item in service["absolute_loader_environment"]],
            ["/a.so", "/b.so", "/c.so", "/from-file"],
        )


class LoaderAndUdevTests(TreeFixture):
    def test_loader_includes_preload_and_writable_search_path(self):
        libdir = self.root / "opt/vendor/lib"
        libdir.mkdir(parents=True)
        libdir.chmod(0o777)
        self.make("etc/ld.so.conf", "include /etc/ld.so.conf.d/*.conf\n")
        self.make("etc/ld.so.conf.d/vendor.conf", "/opt/vendor/lib\n")
        preload = self.make("opt/vendor/lib/preload.so", "x", 0o666)
        self.make("etc/ld.so.preload", "/opt/vendor/lib/preload.so\n")
        loader, warnings = AUDIT.loader_inventory(self.root.resolve())
        self.assertEqual(warnings, [])
        vendor = next(x for x in loader["search_paths"] if x["value"] == "/opt/vendor/lib")
        self.assertTrue(vendor["path_info"]["world_writable"])
        self.assertEqual(loader["preload_entries"][0]["value"], "/opt/vendor/lib/preload.so")
        self.assertTrue(loader["preload_entries"][0]["path_info"]["world_writable"])
        self.assertTrue(preload.exists())

    def test_permissive_udev_rules_keep_location_and_text(self):
        self.make(
            "etc/udev/rules.d/55-test.rules",
            """# ignored
KERNEL==\"safe\", MODE=\"0600\", OWNER=\"root\", GROUP=\"root\"
KERNEL==\"seq\", MODE:=\"0644\", GROUP=\"audio\"
""",
        )
        paths, _ = AUDIT.walk_no_symlinks(self.root.resolve())
        findings, warnings = AUDIT.udev_inventory(self.root.resolve(), paths)
        self.assertEqual(warnings, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["path"], "/etc/udev/rules.d/55-test.rules")
        self.assertEqual(findings[0]["line"], 3)
        self.assertEqual(findings[0]["mode"], "0644")
        self.assertEqual(findings[0]["group"], "audio")
        self.assertIn("KERNEL", findings[0]["text"])

    def test_udev_continuation_retains_first_physical_line(self):
        self.make(
            "etc/udev/rules.d/56-continuation.rules",
            """# one
KERNEL==\"joined\", \\
  OWNER=\"root\"
# four
KERNEL==\"seq\", MODE=\"0664\"
""",
        )
        paths, _ = AUDIT.walk_no_symlinks(self.root.resolve())
        findings, warnings = AUDIT.udev_inventory(self.root.resolve(), paths)
        self.assertEqual(warnings, [])
        self.assertEqual(findings[0]["line"], 5)
        self.assertIn('KERNEL=="seq"', findings[0]["text"])


class CapabilityTests(TreeFixture):
    def test_present_xattr_is_recorded_raw(self):
        tool = self.make("bin/tool", "x", 0o755)
        with mock.patch.object(AUDIT, "get_xattr", return_value=b"\x01\x00\x00\x02abcd"):
            result = AUDIT.capability_inventory(self.root.resolve(), [tool.resolve()])
        self.assertEqual(result["entries"][0]["path"], "/bin/tool")
        self.assertEqual(result["entries"][0]["raw_hex"], "0100000261626364")
        self.assertEqual(result["entries"][0]["decode_status"], "header-only")
        self.assertIn("do not prove", result["interpretation"])

    def test_unavailable_xattrs_are_reported_not_treated_as_absent(self):
        tool = self.make("bin/tool", "x", 0o755)
        error = OSError(getattr(os, "ENOTSUP", 45), "unsupported")
        error.errno = getattr(os, "ENOTSUP", 45)
        with mock.patch.object(AUDIT, "get_xattr", side_effect=error):
            result = AUDIT.capability_inventory(self.root.resolve(), [tool.resolve()])
        self.assertEqual(result["entries"], [])
        self.assertEqual(result["host_xattr_absent"], 0)
        self.assertEqual(result["errors"][0]["kind"], "ENOTSUP")
        self.assertIn("source filesystem", result["interpretation"])


if __name__ == "__main__":
    unittest.main()
