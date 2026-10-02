"""Show that verifier/ is unchanged in logic since the independence freeze.

Compares every verifier/*.py file at the freeze commit (INDEPENDENCE.md) with
the working tree after parsing both into syntax trees. Comments disappear in
parsing and docstrings are removed, so formatting and documentation edits do
not count. String literals are then masked, and any remaining difference is a
change to the code. Literals that differ (message wording) are listed so they
can be read.

    python scripts/check_verifier_unchanged.py [FREEZE_COMMIT]

Exit status 0 means no code change; 1 means a code change was found.
"""

import ast
import pathlib
import subprocess
import sys

FREEZE = "f9b5dba"
ROOT = pathlib.Path(__file__).resolve().parent.parent


def _strip_docstrings(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                node.body = body[1:] or [ast.Pass()]
    return tree


def _strings(tree):
    return [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def _masked(tree):
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            n.value = "<str>"
    return ast.dump(tree, include_attributes=False)


def main(argv):
    freeze = argv[1] if len(argv) > 1 else FREEZE
    listed = subprocess.run(["git", "ls-tree", "-r", "--name-only", freeze, "verifier/"],
                            cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    now = sorted(str(p.relative_to(ROOT)) for p in (ROOT / "verifier").glob("*.py"))
    changed_code = False
    if sorted(listed) != now:
        print(f"file set differs: at {freeze} {sorted(listed)}, now {now}")
        changed_code = True
    for path in sorted(set(listed) & set(now)):
        old_src = subprocess.run(["git", "show", f"{freeze}:{path}"], cwd=ROOT,
                                 capture_output=True, text=True, check=True).stdout
        new_src = (ROOT / path).read_text()
        old, new = _strip_docstrings(ast.parse(old_src)), _strip_docstrings(ast.parse(new_src))
        old_strings, new_strings = _strings(old), _strings(new)
        if _masked(old) != _masked(new):
            print(f"{path}: CODE CHANGED")
            changed_code = True
        elif old_strings != new_strings:
            for a, b in zip(old_strings, new_strings):
                if a != b:
                    print(f"{path}: message text changed\n    was: {a!r}\n    now: {b!r}")
        else:
            print(f"{path}: identical apart from comments and docstrings")
    print("\nverifier/ logic unchanged since the freeze" if not changed_code
          else "\nverifier/ CODE CHANGED since the freeze")
    return 1 if changed_code else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
