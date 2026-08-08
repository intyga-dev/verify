# Changelog

All notable changes to `@intyga/verify` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

## [1.0.0]

Initial public release.

- Offline approval-receipt verification (ES256 and WebAuthn) against a caller-supplied trust
  anchor — no Intyga secret, no network. `AUTO_APPROVED` receipts are refused by default.
- DIV canonical payload builders and verification codes, pinned by shared cross-language golden
  vectors.
- DEWP ledger verification: inclusion proofs with mandatory bounds checks, §5.2 anchor signatures,
  §5.3 anchor-quorum evaluation, §5.4 checkpoint continuity chain, and evidence bundles.
- Zero runtime dependencies (Node ≥ 18, `node:crypto` only).
