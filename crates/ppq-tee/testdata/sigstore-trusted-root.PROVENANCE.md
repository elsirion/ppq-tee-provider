# Sigstore trusted root provenance

Records the origin of `sigstore-trusted-root.json`, the file embedded as
`attest::policy::SIGSTORE_TRUSTED_ROOT`. It is a pinned root of trust: every
Fulcio certificate chain, SCT and Rekor inclusion proof this crate verifies is
checked against the keys in this file, so its provenance is part of the crate's
security argument, not a test-fixture detail. The AMD roots' equivalent is
`amd/PROVENANCE.md`.

Date obtained: 2026-08-15

## Source

Sigstore's public-good TUF repository, `https://tuf-repo-cdn.sigstore.dev/`.

The plain target URL

```
https://tuf-repo-cdn.sigstore.dev/targets/trusted_root.json
```

returns **404**. That repository runs with TUF *consistent snapshots* enabled,
under which targets are served only at their hash-prefixed names
(`targets/<sha256>.trusted_root.json`), and the unprefixed path does not exist.
The file was therefore obtained by walking the TUF chain rather than by
fetching that URL:

```
timestamp.json  →  snapshot v165  →  targets v14  →  hashed target object
```

Each step was verified against the metadata that signed it, and the resulting
target's digest was checked against the entry recorded for it in the signed
`targets` metadata. The file below is that target's contents, unmodified.

## Digest and length

```
6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66  sigstore-trusted-root.json
```

Length: 6787 bytes.

Re-verified against the committed blob (not just the working tree):

```
$ sha256sum crates/ppq-tee/testdata/sigstore-trusted-root.json
6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66  crates/ppq-tee/testdata/sigstore-trusted-root.json
$ wc -c crates/ppq-tee/testdata/sigstore-trusted-root.json
6787 crates/ppq-tee/testdata/sigstore-trusted-root.json
$ git show HEAD:crates/ppq-tee/testdata/sigstore-trusted-root.json | sha256sum
6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66  -
```

## Refreshing it

Pinning means this file does not follow sigstore key rotations on its own. A
refresh is another TUF walk to the current `targets` version, with the new
target's digest recorded here and in the commit that changes the file — never
a bare `curl` of an unverified URL, and never an edit in place.
