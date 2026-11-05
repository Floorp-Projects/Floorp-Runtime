import ast
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path("build/moz.configure/update-programs.configure")
PATCH = ROOT / ".github/patches/upstream/build-moz.configure-update-programs.configure.patch"
NAMES = {
    "mac_prod_requirements_string",
    "mac_relaxed_requirements_string",
    "smauthorizedclients_requirements",
    "requirements_string",
    "generate_smprivilegedexec_requirements",
}


def read_generators(apply_patch):
    source = (ROOT / SOURCE).read_text(encoding="utf-8")
    if apply_patch:
        with tempfile.TemporaryDirectory(prefix="floorp-helper-requirements-") as temp:
            target = Path(temp) / SOURCE
            target.parent.mkdir(parents=True)
            target.write_text(source, encoding="utf-8", newline="\n")
            subprocess.run(["git", "apply", "--check", str(PATCH)], cwd=temp, check=True)
            subprocess.run(["git", "apply", str(PATCH)], cwd=temp, check=True)
            source = target.read_text(encoding="utf-8")
    functions = []
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef) and node.name in NAMES:
            node.decorator_list = []
            functions.append(node)
    if {node.name for node in functions} != NAMES:
        raise AssertionError("The Runtime requirement generators changed")
    namespace = {"escape": escape}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(SOURCE), "exec"), namespace)
    return namespace


class MacHelperRequirementsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.before = read_generators(False)
        cls.after = read_generators(True)

    def assert_production_requirement(self, requirement, identifier):
        self.assertIn(f'identifier "{identifier}"', requirement)
        self.assertIn('certificate leaf[subject.OU] = "DV2U35YBHT"', requirement)
        self.assertIn("anchor apple generic", requirement)
        self.assertIn("certificate 1[field.1.2.840.113635.100.6.2.6]", requirement)
        self.assertIn("certificate leaf[field.1.2.840.113635.100.6.1.13]", requirement)
        self.assertNotIn("43AQ936H96", requirement)

    def test_unpatched_runtime_requires_the_wrong_publisher(self):
        requirement = self.before["smauthorizedclients_requirements"](False, "app.floorp.Floorp")
        self.assertIn('certificate leaf[subject.OU] = "43AQ936H96"', requirement)
        with self.assertRaises(AssertionError):
            self.assert_production_requirement(requirement, "app.floorp.Floorp")

    def test_helpers_require_the_floorp_client_and_developer_id_certificate(self):
        for identifier in ("app.floorp.Floorp", "app.floorp.FloorpDaylight"):
            with self.subTest(identifier=identifier):
                requirement = self.after["smauthorizedclients_requirements"](False, identifier)
                self.assert_production_requirement(requirement, identifier)

    def test_app_requires_both_floorp_signed_helpers(self):
        entries = self.after["generate_smprivilegedexec_requirements"](False)
        requirements = plistlib.loads(f"<plist><dict>{entries}</dict></plist>".encode())
        self.assertEqual(set(requirements), {"org.mozilla.updater", "org.mozilla.dmgInstallHelper"})
        for identifier, requirement in requirements.items():
            with self.subTest(identifier=identifier):
                self.assert_production_requirement(requirement, identifier)

    def test_developer_opt_in_behavior_is_not_enabled_or_changed(self):
        self.assertEqual(
            self.before["generate_smprivilegedexec_requirements"](True),
            self.after["generate_smprivilegedexec_requirements"](True),
        )
        self.assertEqual(
            self.before["smauthorizedclients_requirements"](True, "app.floorp.Floorp"),
            self.after["smauthorizedclients_requirements"](True, "app.floorp.Floorp"),
        )


if __name__ == "__main__":
    unittest.main()
