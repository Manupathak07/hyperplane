"""Ingestion layer: log parsers + normalised event schema.

Scope rules (locked Week 4):
- Parsers do format → NormalisedEvent mapping only. No correlation, no
  severity enrichment, no threat intel. Those are agent jobs in Weeks 6+.
- If a parser can't make sense of a payload, it returns a NormalisedEvent
  with event_type="parse_failed" and the raw text preserved. We never reject
  input — bad data is still data, and it makes bad parsers visible.
- Every NormalisedEvent MUST set: domain, event_type, observed_at, raw,
  parser. These are the contract.
"""
