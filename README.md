```markdown
# Covalence SDK

A secure, high‑performance Python client for Covalence.

## Features

- One‑time key swap + JWT tokens  
- Automatic token refresh (thread‑safe, proactive)  
- Connection pooling & retries  
- Provider→URL map (just `provider="openai"`)  
- Pluggable logging  

## Installation

```bash
pip install covalence-sdk
```

## Quickstart

```python
from covalence import Client

client = Client(
  email="alice@acme.com",
  password="hunter2",
  openai_api_key="sk-REALLY_SECRET",   # optional: can read from OPENAI_API_KEY
  provider="openai"                    # auto‑fills https://api.openai.com/v1
)

# Register a model
client.register_model(name="my-gpt4", model="gpt-4o")

# Chat
reply = client.chat(
  model="my-gpt4",
  messages=[{"role":"user","content":"Hello!"}]
)
print("LLM → ", reply)

# Logout
client.logout()
```

## License

MIT