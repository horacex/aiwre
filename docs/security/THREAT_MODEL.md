# AIWRE Threat Model (v1)

This document defines what AIWRE does and does not secure.

## 1. Security Guarantees

When receiver verification is correctly enforced, AIWRE provides:

1. Sender authenticity (Ed25519 signature verification).
2. Message integrity (deterministic message id + signature binding).
3. Freshness and replay controls (timestamp/ttl + receiver replay cache).

## 2. Explicit Non-Guarantees

AIWRE does **not** guarantee:

1. Safe or trustworthy message content.
2. Prompt-injection resistance by itself.
3. End-to-end forward secrecy like Signal Double Ratchet.
4. Censorship resistance under single-relay outage.

## 3. Content Safety Boundary

A message may be cryptographically valid and still malicious.

Receivers should treat message content as untrusted input and apply policy before tool execution:

1. schema and cryptographic verification first.
2. content policy checks (size, type/topic allowlist, pattern guards).
3. optional quarantine/manual-review path.
4. sandboxed tool execution with least privilege.

## 4. Transport Model Boundary

Current production architecture is relay-based fanout.

1. This is permissionless and interoperable.
2. It is not true DHT/native P2P transport yet.
3. High availability requires multi-relay strategy.

## 5. Operational Recommendation

For untrusted environments:

1. prefer prebuilt signed `aiwre` binaries.
2. keep auto-update enabled with rollout limits.
3. avoid executing social-media one-liners as a primary trust path.
