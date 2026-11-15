"""Every global name the scripts use is defined where static analysis can see it.

scripts/publish-kits.py once injected names with globals()[name] = ..., which
hid 66 undefined names from every linter. This compiles each script and fails
on a global that is neither a builtin, an import, a definition nor an
assignment; it needs no third-party package.
"""
import builtins
import pathlib
import symtable
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPTS = sorted((ROOT / "scripts").glob("*.py"))
MODULE_NAMES = {"__file__", "__name__", "__doc__", "__spec__", "__loader__", "__package__", "__builtins__"}


def undefined_globals(source, filename="<script>"):
    top = symtable.symtable(source, filename, "exec")
    defined = set(MODULE_NAMES) | set(dir(builtins))
    defined |= {s.get_name() for s in top.get_symbols() if s.is_assigned() or s.is_imported() or s.is_namespace()}
    used = {}

    def walk(table):
        for symbol in table.get_symbols():
            if table is not top and symbol.is_global():
                if symbol.is_declared_global() and symbol.is_assigned():
                    defined.add(symbol.get_name())
                if symbol.is_referenced():
                    used.setdefault(symbol.get_name(), table.get_name())
        for child in table.get_children():
            walk(child)

    walk(top)
    return {name: scope for name, scope in used.items() if name not in defined}


class ScriptNames(unittest.TestCase):
    def test_every_global_a_script_uses_is_defined(self):
        for path in SCRIPTS:
            with self.subTest(script=path.name):
                self.assertEqual(undefined_globals(path.read_text(), str(path)), {}, path.name)

    def test_the_check_catches_names_injected_through_globals(self):
        source = (
            "for _name in ('shared',):\n"
            "    globals()[_name] = len\n"
            "def use():\n"
            "    return shared()\n"
        )
        self.assertEqual(undefined_globals(source), {"shared": "use"})

    def test_the_check_accepts_defined_and_builtin_names(self):
        source = (
            "import os\n"
            "from sys import argv\n"
            "LIMIT = 1\n"
            "def helper():\n"
            "    global COUNT\n"
            "    COUNT = 2\n"
            "def use():\n"
            "    return os, argv, LIMIT, COUNT, helper, len, __file__\n"
            "class Thing:\n"
            "    def method(self):\n"
            "        return Thing, use\n"
        )
        self.assertEqual(undefined_globals(source), {})


if __name__ == "__main__":
    unittest.main()
