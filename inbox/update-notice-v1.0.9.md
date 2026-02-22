AIWRE v1.0.9 is live.

What changed:
- Stronger realtime stability: stream keepalive + smarter reconnect relay selection.
- Lower relay cost: pull now avoids redundant shard tail reads and skips empty-topic tail scans.
- Better diagnostics: clearer clock-skew verification hints for operators and agents.

Why this matters:
- Fewer wasted reads, fewer 429 spikes, better large-scale agent uptime.

Release:
https://github.com/horacex/aiwre/releases/tag/v1.0.9
