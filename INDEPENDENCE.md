# Verifier independence

The verifier (`verifier/`) was written without access to the prover's
cryptography (`crypto/`, `tally/`) and was completed before that code entered
this repository. This file records the evidence.

## What the verifier was built from

- The specification, `spec/SPEC.md`, and the test vectors in `spec/vectors/`.
- Exported bulletin boards and signature files, as data.
- The integration code outside `crypto/` and `tally/` (`run_election.py`,
  `board/`, `app/`), read only after the verifier's checks were complete, to
  locate defects in how boards were produced. Nothing in `verifier/` derives
  from it.

`verifier/` never imports from `crypto/` or `tally/`;
`tests/test_independence.py` enforces this on every test run.

## The freeze

The verifier was frozen at commit `f9b5dba`, before `crypto/` and `tally/` were
added (commit `2343598`). At the freeze its files hashed as follows:

```
f7ea53ab716a647dbede20b1d35a94e152d81937ce319ac6d9c9d082cb2fe2b9  verifier/__init__.py
29477f223836656144dcdabf31b41d67be56884dbcc4f2625cfcebc17e578339  verifier/__main__.py
13366ca7d7bea6030cc5370dba9470fb0bcaa7d8c289b0e49711617c828a10a4  verifier/encoding.py
be44d9a138b1952c3cd653c08d4007048cce0e4dd379c5fdf681a0fab9f16822  verifier/group.py
e701b2409444df0b92bc1d8dcb0c5e3775e7002dce4f614affdffdb48103fca0  verifier/hashes.py
df32344fd239594c9cef68dfb7af88b417ca382eab9d34b93b8bb79ff59ce079  verifier/integrity.py
1d6134650fe6abc0d0bafc8943112cfdd6d3a33fc70822b19d646f42f78f63aa  verifier/parse.py
ca9dcd03d88cfa6bfb6e71576db093b25b6249c5ec90c977e8dd6ca6b9600d12  verifier/proofs.py
76eb519e6e7e7c209e483c985467de4f392bf155b1ca65091bd2fb22e30a89cc  verifier/result.py
c9a30bb340c4929020b5ffbe919ae099a1ac7d7cedc083299317de728d1d803b  verifier/spoils.py
910b008d1c58a1cef3c83e78b046729f4b1e6aa786107a02c449619fbabc470a  verifier/tally.py
6bf871b006a98f829b971681a50587d89463a98844edc6ca6aa4ae10922e5ff0  verifier/verify.py
```

## Checking that the logic has not changed since

```
python scripts/check_verifier_unchanged.py
```

parses every verifier file at the freeze commit and in the working tree,
discards comments and docstrings, and compares the code. Since the freeze,
only documentation and the wording of two messages have changed; the script
lists both, and reports any change to code.
