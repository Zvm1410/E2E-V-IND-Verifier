# Verifier independence record

Frozen at tag `verifier-independent-v1` (the commit that adds this file), 2026-10-02T07:51Z, before any file from `crypto/` or `tally/` entered this repository or this author's view.

## What the verifier was built from

- `spec/SPEC.md` (revisions 2 and 3) and the test vectors in `spec/vectors/`
  (`group.json`, `encoding.json`, `base_hash.json`, `decryption.json`).
- Exported boards and signature files (`tests/fixtures/boards/`), as data.
- Basket C's integration files outside `crypto/` and `tally/`
  (`run_election.py`, `board/`, `app/`), read after D2 to D7 were complete,
  to locate the pre-poll bugs; nothing in `verifier/` was derived from them.

It never imported, and was never written from, `crypto/` or `tally/`.
`tests/test_independence.py` enforces the import half mechanically.

## How to check it

Every file below must hash to the value shown at the tagged commit. Any later
change to `verifier/` appears in `git log -- verifier/` after this tag and is,
by definition, made with the prover code present in the repository.

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
