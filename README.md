# vdp-rs2scope

Authorized CodeRabbit VDP research fixture (own account `coderabbit-vdp-research4`, own repos only).
Purpose: F-RUNNERSINKS-02 task 1 — determine the SCOPE of the review runner's per-run auth material.

The module in `mdx/` executes at review time via a markdownlint `customRules` entry and performs
introspection only: (1) offline JWT decode of the material (audience, issuer, subject, expiry,
scope / repository list) with NO network use, and (2) ONLY if the material is not a JWT, exactly
ONE read-only `GET /installation/repositories?per_page=1` through the runner's own egress sidecar
to determine the scope of the identity the sidecar exchanges into. The material is used in memory
only and is never written to disk, transmitted (not even partially) or printed. Repository
identifiers not owned by `coderabbit-vdp-research4` are reduced to `<foreign>` before anything
leaves the runner; a raw response body is forwarded only if it contains no foreign identifiers.
