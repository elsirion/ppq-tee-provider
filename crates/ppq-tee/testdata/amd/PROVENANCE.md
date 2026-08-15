# AMD SEV-SNP root certificate provenance

Date obtained: 2026-08-15

## Why not AMD KDS

The brief's canonical source is AMD's Key Distribution Service
(`https://kdsintf.amd.com/vcek/v1/{Milan,Genoa,Turin}/cert_chain`), which
returns each product's ASK+ARK chain as a single PEM document. `kdsintf.amd.com`
is network-blocked from the environment this task was executed in — TCP
connections to it (165.204.91.78/79:443) time out. The human operator approved
vendoring the same root certificates from `virtee/sev`, the VirTEE project's
Rust SEV crate, as an alternative source, on the condition that each file be
verified against known-good SHA-256 digests before use.

## Source

Repository: `virtee/sev` (https://github.com/virtee/sev), `main` branch.

Raw URLs fetched:

- `https://raw.githubusercontent.com/virtee/sev/main/src/certs/snp/builtin/milan/ark.pem`
- `https://raw.githubusercontent.com/virtee/sev/main/src/certs/snp/builtin/milan/ask.pem`
- `https://raw.githubusercontent.com/virtee/sev/main/src/certs/snp/builtin/genoa/ark.pem`
- `https://raw.githubusercontent.com/virtee/sev/main/src/certs/snp/builtin/genoa/ask.pem`
- `https://raw.githubusercontent.com/virtee/sev/main/src/certs/snp/builtin/turin/ark.pem`
- `https://raw.githubusercontent.com/virtee/sev/main/src/certs/snp/builtin/turin/ask.pem`

## SHA-256 of each source file (verified against digests supplied by the
## controller before any file was used as a trust anchor)

```
96bff94e97e2b7ddf4bf3b9b7f780f94a46b8c51f52abfdcc283be7df36ce405  genoa/ark.pem
22fea250e0390b22008c9a415f4bd915ae8cef4a240f9d21702e84eb250b9186  genoa/ask.pem
8c109952166431ffad8cb9a3d54f3d20ffbbb58164f0d54be3457bf0ece9e0d8  milan/ark.pem
8da3a65af1cb7cb90a21fac78431a2431a9ee7811f48c36569c53fb80ad31fee  milan/ask.pem
b69c981fe0216c3d8e682eb6f480c6879497103071e52b5e603178638db8f68d  turin/ark.pem
c72a54fb75a0a06b0c8dbf68b04893d0891751b94ce4da8231d11fd18a0da944  turin/ask.pem
```

All six matched exactly (`sha256sum -c` reported `OK` for every file). No file
was used as a trust anchor before its digest was confirmed.

## Assembly

Each embedded `crates/ppq-tee/testdata/amd/{Milan,Genoa,Turin}.pem` is the
product's `ask.pem` concatenated with its `ark.pem` (ASK at PEM index 0, ARK
at index 1), because Task 6 parses these files with
`Certificate::load_pem_chain()` expecting that order — the same order AMD
KDS's `cert_chain` endpoint returns. Each source file already ends in a
trailing newline, so the concatenation cleanly separates the two `-----END
CERTIFICATE-----` / `-----BEGIN CERTIFICATE-----` boundaries.

## Independent cross-check

The Genoa ARK and ASK downloaded above are byte-identical to the copies
embedded in Tinfoil's own JavaScript verifier
(`tinfoilsh/tinfoil-js`, `packages/verifier/src/sev/certs.ts`, `main` branch),
an independent source unrelated to `virtee/sev`. The PEM bodies extracted from
that file hash to the same SHA-256 digests as `genoa/ark.pem` and
`genoa/ask.pem` above:

```
96bff94e97e2b7ddf4bf3b9b7f780f94a46b8c51f52abfdcc283be7df36ce405  (ark, both sources)
22fea250e0390b22008c9a415f4bd915ae8cef4a240f9d21702e84eb250b9186  (ask, both sources)
```

Genoa is also the product line PPQ's live enclave actually uses — its VCEK is
issued by `SEV-Genoa` — so Task 6's chain verification against the live VCEK
empirically exercises and confirms the embedded Genoa pair. Milan and Turin
are structurally verified (correct PEM, correct digest against the pinned
hashes above) but are not exercised by this enclave's live attestation.
