# ScrubJay

Sanitize sensitive data in security logs before sending to LLM APIs.

## Installation

```bash
pip install scrubjay
```

## Quick Start

```python
from scrubjay import SanitizeSession

session = SanitizeSession(profiles=["okta"])
result = session.sanitize(raw_data)
# Send result.sanitized_data to your LLM
restored = session.restore(llm_response)
```
