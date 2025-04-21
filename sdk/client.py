import os
import time
import threading
import logging
import jwt
import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

from .utils import get_provider_url
from .models import (
  LoginReq, LoginResp,
  SwapReq, SwapResp,
  RefreshReq, RefreshResp,
  RegisterModelReq
)
from .exceptions import (
  AuthenticationError,
  RefreshError,
  RegistrationError
)

# Proxy configuration
PROXY_BASE = "https://api.covalence.run"
PROXY_API_URL = f"{PROXY_BASE}/v1"
# Default timeout for all HTTP calls (seconds)
HTTP_TIMEOUT = float(os.getenv("COVALENCE_HTTP_TIMEOUT", "10"))

class Covalence:
  def __init__(self, email: str | None = None, password: str | None = None):
    # Credentials
    self.email = email or os.getenv("COVALENCE_EMAIL")
    self.password = password or os.getenv("COVALENCE_PASSWORD")
    if not (self.email and self.password):
      raise AuthenticationError(
        "Email and password must be provided via args or COVALENCE_EMAIL/PASSWORD env vars."
      )

    # Logger
    self.logger = logging.getLogger(__name__)
    self.logger.setLevel(logging.INFO)

    # HTTP session with retries and timeouts
    self._session = requests.Session()
    retry_strategy = Retry(
      total=3,
      backoff_factor=0.3,
      status_forcelist=[502, 503, 504],
      raise_on_status=False,
      respect_retry_after_header=True
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    self._session.mount("https://", adapter)
    self._session.mount("http://", adapter)

    # Prevent redirects to untrusted URLs
    self._session.max_redirects = 3

    # Authenticate via proxy (wraps Supabase)
    self._login()

    # Lock for thread-safe token refresh
    self._lock = threading.Lock()

  def _login(self):
    """
    Authenticate via proxy endpoint (wraps Supabase). Store session tokens.
    """
    payload = LoginReq(email=self.email, password=self.password).model_dump(mode="json")
    try:
      resp = self._session.post(
        f"{PROXY_BASE}/auth/login",
        json=payload,
        timeout=HTTP_TIMEOUT,
        allow_redirects=False
      )
    except requests.RequestException as e:
      self.logger.error("Network error during login", exc_info=e)
      raise AuthenticationError("Network error during login")

    if resp.status_code != 200:
      self.logger.warning("Login failed", extra={"status": resp.status_code})
      raise AuthenticationError(f"Login failed ({resp.status_code})")

    session = LoginResp(**resp.json())
    self._session_jwt = session.access_token
    self._session_refresh = session.refresh_token
    self._session_expiry = session.expires_at
    # Do not log token details
    self.logger.debug("Logged in: session acquired; user_id=%s", session.user.id)

  def register_model(self, name: str, model: str, provider: str, api_key: str | None = None, custom_api_url: str | None = None) -> dict:
    """
    Swap raw provider key for proxy tokens, then register a model alias.
    """
    key = api_key or os.getenv(f"{provider.upper()}_API_KEY")
    if not key:
      raise AuthenticationError(
        f"Missing API key for '{provider}' (env var {provider.upper()}_API_KEY or param required)."
      )

    self._swap_key(provider, key)

    api_url = custom_api_url or get_provider_url(provider)
    payload = RegisterModelReq(
      name=name,
      model=model,
      provider=provider,
      api_url=api_url
    ).model_dump(mode="json")
    headers = {"Authorization": f"Bearer {self._access_token}"}
    try:
      resp = self._session.post(
        f"{PROXY_BASE}/model/register",
        headers=headers,
        json=payload,
        timeout=HTTP_TIMEOUT,
        allow_redirects=False
      )
    except requests.RequestException as e:
      self.logger.error("Network error during model registration", exc_info=e)
      raise RegistrationError("Network error during model registration")

    if resp.status_code != 200:
      self.logger.warning("Model registration failed", extra={"status": resp.status_code})
      raise RegistrationError(f"Model registration failed ({resp.status_code})")

    self.logger.info("Model '%s' registered for provider '%s'", name, provider)
    return resp.json()

  def get_user_details(self) -> dict:
    """
    Retrieve info about the authenticated user.
    """
    token = self.token()
    headers = {"Authorization": f"Bearer {token}"}
    resp = self._session.get(
      f"{PROXY_API_URL}/user/me",
      headers=headers,
      timeout=HTTP_TIMEOUT,
      allow_redirects=False
    )
    try:
      resp.raise_for_status()
    except requests.HTTPError:
      self.logger.error("Failed to fetch user details: %s", resp.text)
      raise
    return resp.json()

  def _swap_key(self, provider: str, key: str):
    """
    Exchange raw API key for proxy tokens.
    """
    payload = SwapReq(provider=provider, api_key=key).model_dump(mode="json")
    headers = {"Authorization": f"Bearer {self._session_jwt}"}
    try:
      resp = self._session.post(
        f"{PROXY_BASE}/auth/token",
        headers=headers,
        json=payload,
        timeout=HTTP_TIMEOUT,
        allow_redirects=False
      )
    except requests.RequestException as e:
      self.logger.error("Network error during key swap", exc_info=e)
      raise AuthenticationError("Network error during key swap")

    if resp.status_code != 200:
      self.logger.warning("Key swap failed", extra={"status": resp.status_code})
      raise AuthenticationError(f"Key swap failed ({resp.status_code})")

    data = SwapResp(**resp.json())
    self._access_token = data.access_token
    self._refresh_token = data.refresh_token
    claims = jwt.decode(self._access_token, options={"verify_signature": False})
    self._expiry = claims.get("exp", 0)
    self.logger.debug("Proxy tokens acquired; expiry=%s", self._expiry)

  def _refresh(self):
    """
    Refresh proxy access token if near expiry.
    """
    with self._lock:
      if time.time() < self._expiry - 60:
        return
      try:
        payload = RefreshReq(refresh_token=self._refresh_token).model_dump(mode="json")
        resp = self._session.post(
          f"{PROXY_BASE}/auth/refresh",
          json=payload,
          timeout=HTTP_TIMEOUT,
          allow_redirects=False
        )
      except requests.RequestException as e:
        self.logger.error("Network error during token refresh", exc_info=e)
        raise RefreshError("Network error during token refresh")

      if resp.status_code != 200:
        self.logger.warning("Token refresh failed", extra={"status": resp.status_code})
        raise RefreshError(f"Token refresh failed ({resp.status_code})")

      self._access_token = RefreshResp(**resp.json()).access_token
      claims = jwt.decode(self._access_token, options={"verify_signature": False})
      self._expiry = claims.get("exp", 0)
      self.logger.debug("Access token refreshed; expiry=%s", self._expiry)

  def token(self) -> str:
    """
    Return a valid proxy access token, refreshing if necessary.
    """
    if time.time() > self._expiry - 60:
      self._refresh()
    return self._access_token

  def url(self) -> str:
    """
    Return the proxy API base URL (/v1).
    """
    return PROXY_API_URL
