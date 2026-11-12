#!/usr/bin/env python3
"""Exercise patched Gecko text transforms with the matching Fluent resolver."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.read_text(encoding="utf-8")
    functions = []
    for name in ["transform_brand", "transform_accented", "transform_bidi"]:
        match = re.search(r"^fn " + name + r"\(.*?^\}", source, re.M | re.S)
        if not match:
            raise ValueError(f"Missing production function: {name}")
        functions.append(match.group())
    if "PseudoStrategy::None => bundle.set_transform(Some(transform_brand))" not in source:
        raise ValueError("Production bundle does not install its branding transform")
    with tempfile.TemporaryDirectory(prefix="floorp-fluent-brand-") as directory:
        root = Path(directory)
        (root / "src").mkdir()
        (root / "Cargo.toml").write_text('''[package]
name = "floorp-fluent-brand-regression"
version = "0.1.0"
edition = "2021"
[dependencies]
fluent-bundle = "=0.16.0"
fluent-pseudo = "=0.3.3"
''', encoding="utf-8")
        tests = Path(__file__).with_name("fluent_branding_cases.rs").read_text(encoding="utf-8")
        code = "use std::borrow::Cow;\nuse fluent_pseudo::transform_dom;\n" + "\n\n".join(functions) + tests
        (root / "src/lib.rs").write_text(code, encoding="utf-8")
        result = subprocess.run(["cargo", "test", "--manifest-path", str(root / "Cargo.toml")], check=False)
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
