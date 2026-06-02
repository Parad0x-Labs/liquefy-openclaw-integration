# Correction vs Instruction Tagger

Detects when a message corrects a prior one and builds an active state
where corrections override originals.

The problem nobody benchmarks: "use Redis" at msg 20, "actually use
Postgres" at msg 47. Standard compression keeps both. This tagger
supersedes Redis, surfaces only Postgres in activeInstructions.

## Usage

```python
from correction_intent import tag_messages, build_active_state, inject_active_state

tagged = tag_messages(messages)
state = build_active_state(tagged)
system_injection = inject_active_state(state)
# inject into system prompt — agent sees CURRENT STATE, not history
```

## What it detects

- CORRECTION: "actually", "scratch that", "instead", "I meant", implicit topic override
- INSTRUCTION: new directive
- ADDITIVE: "also", "additionally" — extends without overriding
- QUERY: question, not actionable
- ACK: "ok", "got it", "understood"

## Correction chain receipt

```python
from correction_intent import correction_chain_receipt
receipt = correction_chain_receipt(state, session_id)
# receipt["chain_root"] anchors to Solana via receipt_anchor
```

Part of the Parad0x Labs stack: github.com/Parad0x-Labs/dna-x402
