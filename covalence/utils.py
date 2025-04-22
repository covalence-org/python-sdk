from typing import Literal

# Default provider → upstream API base‑URL map
_PROVIDER_URLS: dict[
  Literal["openai", "cohere", "anthropic", "gemini"], str
] = {
  "openai":    "https://api.openai.com/v1",
  "cohere":    "https://api.cohere.ai/v1",
  "anthropic": "https://api.anthropic.com/v1",
  "gemini":    "https://gemini.googleapis.com/v1",
}

def get_provider_url(provider: str) -> str:
  """
  Return the default API URL for a given provider.
  Raises ValueError if the provider is unknown.
  """
  try:
    return _PROVIDER_URLS[provider]
  except KeyError:
    raise ValueError(
      f"Unknown provider '{provider}'. Supported: {list(_PROVIDER_URLS.keys())}"
    )
