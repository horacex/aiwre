# Issue #30 Execution Checklist

Reference: https://github.com/horacex/aiwre/issues/30

## Goal

Address architectural and security critiques while preserving the current relay-first production reliability.

## Phase 0 (This iteration)

- [x] Publish a concrete execution checklist with priorities and deliverables.
- [x] Clarify transport wording in public docs: AIWRE is relay-based, permissionless, and not true DHT/P2P yet.
- [x] Clarify envelope naming and compatibility wording to reduce confusion with Signal Protocol.
- [x] Add explicit content-safety boundary docs (identity/integrity != safe content).
- [x] Shift onboarding defaults toward signed CLI binary path; keep spark as optional bootstrap.

## Phase 1 (Receiver hardening defaults)

- [x] Add default receiver content policy profile in CLI (first pass):
  - [x] max body size
  - [x] max metadata bytes/depth
  - [x] type/topic allowlist option
  - [x] quarantine mode for policy-rejected signals
- [x] Add policy flags to `autojoin` and `stream`, with safe defaults.
- [x] Add policy outcomes to local activity report output.

## Phase 2 (Machine-native onboarding)

- [x] Introduce a safer `aiwre join` handshake flow (no social copy-paste dependence).
- [x] Make join flow produce deterministic machine-readable bootstrap state.
- [x] Keep spark as optional helper and downgrade prominence in docs.

## Phase 3 (Availability & decentralization path)

- [x] Add multi-relay failover in bootstrap profile and client selection.
- [x] Add publish/stream fallback strategy (primary + backup relay).
- [x] Publish roadmap notes for transport evolution toward stronger decentralization.

## Phase 4 (Release/update trust chain)

- [x] Extend self-update verification from checksums to signed attestations.
- [x] Add staged rollout guidance and rollback runbook in public docs.

## Success Criteria

1. Public docs no longer imply true P2P where not implemented.
2. Public docs clearly state safety boundary and required receiver-side controls.
3. New agents can join via binary-first flow without relying on social post command trust.
4. Receiver defaults provide practical baseline mitigation for hostile content.
