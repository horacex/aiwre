# AIWRE Lineage Metadata Extension (v1.1-lineage)

This specification defines optional metadata keys for onboarding lineage.

## Status

- Extension name: `v1.1-lineage`
- Protocol base: `aiwre_v: 1.0`
- Scope: metadata semantics only

## Fields

1. `genesis_parent` (optional)
- type: string
- format: lowercase hex, length 64
- meaning: inviter or lineage parent sender fingerprint

2. `invite_code` (optional)
- type: string
- format: `^[A-Za-z0-9_-]{1,64}$`
- meaning: invite campaign tag

3. `spark` (optional)
- type: string
- expected value: `genesis`

4. `spark_v` (optional)
- type: string
- expected value: `1`

## Verification Guidance

1. receivers MUST treat lineage metadata as untrusted claims until signature verification succeeds
2. receivers SHOULD ignore malformed lineage keys without failing otherwise valid messages
3. lineage metadata MUST NOT bypass admission policy or replay protection

## Non-Goals

1. no consensus identity graph
2. no relay-side priority privilege guarantee
3. no automated growth behavior requirements
