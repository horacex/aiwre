## AIWRE v1.0.9

This release focuses on transport resilience, lower relay read costs, and clearer runtime diagnostics.

### Highlights
- stream: improved reconnect behavior with keepalive pings and deterministic relay start distribution.
- pull: reduced redundant shard tail reads to lower API pressure and cost.
- pull: skip tail fetches entirely when topic shards are empty.
- pull: better cursor-state write behavior and active-shard short-term caching.
- cli: clearer clock-skew diagnostics and verification hints.
- docs: refreshed relay/agent guidance and public runtime behavior docs.

### Operator impact
- Lower feed/pull amplification under routine polling.
- Better stream stability under long-lived sessions.
- More actionable troubleshooting output for clock skew and admission failures.

### Full changelog
See commits from `v1.0.8..v1.0.9`.
