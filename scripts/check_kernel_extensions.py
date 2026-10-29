"""Check the optional pillar extensions against the architecture's inventory."""
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath

PREFIX = "rust/kernel/src/extensions/"
TABLE_ID = "storage-pillar-extension-inventory"


class ExtensionInventory(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_table = False
        self.in_code = False
        self.table_count = 0
        self.text = []
        self.paths = []

    def handle_starttag(self, tag, attrs):
        if tag == "table" and dict(attrs).get("id") == TABLE_ID:
            self.in_table = True
            self.table_count += 1
        elif tag == "code" and self.in_table:
            self.in_code = True
            self.text = []

    def handle_data(self, data):
        if self.in_code:
            self.text.append(data)

    def handle_endtag(self, tag):
        if tag == "code" and self.in_code:
            text = "".join(self.text).strip()
            if text.startswith(PREFIX):
                self.paths.append(text)
            self.in_code = False
        elif tag == "table":
            self.in_table = False


def check(root):
    inventory = ExtensionInventory()
    inventory.feed((root / "docs/KERNEL-ARCHITECTURE.html").read_text(encoding="utf-8"))
    if inventory.table_count != 1 or not inventory.paths:
        raise ValueError("The architecture must contain one nonempty extension inventory")
    paths = [PurePosixPath(path) for path in inventory.paths]
    if len(set(paths)) != len(paths):
        raise ValueError("The extension inventory contains duplicate declarations")
    parent = PurePosixPath(PREFIX)
    if any(path.parent != parent or path.suffix != ".rs" or path.name == "mod.rs" for path in paths):
        raise ValueError("Extension declarations must name direct Rust modules in extensions/")
    expected = {path.name for path in paths} | {"mod.rs"}
    actual = {path.name for path in (root / PREFIX).glob("*.rs")}
    if actual != expected:
        raise ValueError(f"Extension inventory differs: unexpected={sorted(actual - expected)}, missing={sorted(expected - actual)}")
    return sorted(expected)


if __name__ == "__main__":
    print("Storage pillar extension inventory OK: " + ", ".join(check(Path(__file__).resolve().parents[1])))
