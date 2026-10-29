"""The documented extension inventory fails closed on drift and malformed rows."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_kernel_extensions import check, PREFIX, TABLE_ID


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "docs").mkdir()
        (self.root / PREFIX).mkdir(parents=True)
        for name in ["mod.rs", "optional.rs"]:
            (self.root / PREFIX / name).write_text("", encoding="utf-8")
        self.document([PREFIX + "optional.rs"])

    def document(self, paths):
        cells = "".join(f"<tr><td><code>{path}</code></td></tr>" for path in paths)
        (self.root / "docs/KERNEL-ARCHITECTURE.html").write_text(
            f'<table id="{TABLE_ID}"><tbody>{cells}</tbody></table>', encoding="utf-8")

    def test_documented_modules_match(self):
        self.assertEqual(check(self.root), ["mod.rs", "optional.rs"])

    def test_undocumented_module_is_refused(self):
        (self.root / PREFIX / "misplaced.rs").write_text("", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unexpected=.*misplaced"):
            check(self.root)

    def test_missing_documented_module_is_refused(self):
        self.document([PREFIX + "missing.rs"])
        with self.assertRaisesRegex(ValueError, "missing=.*missing"):
            check(self.root)

    def test_escaping_or_duplicate_rows_are_refused(self):
        for paths in [[PREFIX + "../outside.rs"], [PREFIX + "optional.rs"] * 2, []]:
            self.document(paths)
            with self.assertRaises(ValueError):
                check(self.root)


if __name__ == "__main__":
    unittest.main()
