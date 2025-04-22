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
  AuthReq, AuthResp,
  SwapReq, SwapResp,
  RefreshReq, RefreshResp,
  RegisterModelReq,
  UserResp
)
from .exceptions import (
  AuthenticationError,
  RefreshError,
  RegistrationError
)

DEFAULT_PROXY_BASE = "https://api.covalence.run"

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
    self._http_session = requests.Session()
    retry_strategy = Retry(
      total=3,
      backoff_factor=0.3,
      status_forcelist=[502, 503, 504],
      raise_on_status=False,
      respect_retry_after_header=True
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    self._http_session.mount("https://", adapter)
    self._http_session.mount("http://", adapter)

    # Prevent redirects to untrusted URLs
    self._http_session.max_redirects = 3

    # Proxy configuration
    self.proxy_base = os.getenv("COVALENCE_PROXY_BASE", DEFAULT_PROXY_BASE)
    self.proxy_api_url = f"{self.proxy_base}/v1"
    self.logger.info(f"Using proxy: {self.proxy_api_url}")
    self.http_timeout = float(os.getenv("COVALENCE_HTTP_TIMEOUT", "10"))

    # Authenticate via proxy (wraps Supabase)
    self._login()

    # Lock for thread-safe token refresh
    self._lock = threading.Lock()

  @classmethod
  def sign_up(cls, email: str, password: str) -> "Covalence":
    """
    Create a new Covalence account and return an instance of the class.
    """
    # Proxy configuration
    proxy_base = os.getenv("COVALENCE_PROXY_BASE", DEFAULT_PROXY_BASE)
    http_timeout = float(os.getenv("COVALENCE_HTTP_TIMEOUT", "10"))

    payload = AuthReq(email=email, password=password).model_dump(mode="json")
    try:
      resp = requests.post(
        f"{proxy_base}/auth/signup",
        json=payload,
        timeout=http_timeout,
        allow_redirects=False
      )
    except requests.RequestException as e:
      raise AuthenticationError("Network error during signup") from e

    if resp.status_code != 200:
      raise AuthenticationError(f"Signup failed ({resp.status_code})")

    return cls(email=email, password=password)

  def _login(self):
    """
    Authenticate via proxy endpoint (wraps Supabase). Store session tokens.
    """
    payload = AuthReq(email=self.email, password=self.password).model_dump(mode="json")
    try:
      resp = self._http_session.post(
        f"{self.proxy_base}/auth/login",
        json=payload,
        timeout=self.http_timeout,
        allow_redirects=False
      )
    except requests.RequestException as e:
      self.logger.error("Network error during login", exc_info=e)
      raise AuthenticationError("Network error during login")

    if resp.status_code != 200:
      self.logger.warning("Login failed", extra={"status": resp.status_code})
      raise AuthenticationError(f"Login failed ({resp.status_code}): {resp.json().get("error")}")
    self._session = AuthResp(**resp.json())
    self.logger.info("Login successful: %s", self._session.user.email)
    # Do not log token details
    # self.logger.debug("Logged in: session acquired; user_id=%s", session.user.id)

  def register_model(self, name: str, model: str, provider: str, api_key: str | None = None, custom_api_url: str | None = None) -> dict:
    """
    Swap raw provider key for proxy tokens, then register a model alias.
    """
    key = api_key or os.getenv(f"{provider.upper()}_API_KEY")
    if not key:
      raise AuthenticationError(
        f"Missing API key for '{provider}' (env var {provider.upper()}_API_KEY or param required)."
      )
    api_url = custom_api_url or get_provider_url(provider)
    payload = RegisterModelReq(
      name=name,
      model=model,
      provider=provider,
      api_url=api_url
    ).model_dump(mode="json")
    headers = {"Authorization": f"Bearer {self._session.access_token}"}
    try:
      resp = self._http_session.post(
        f"{self.proxy_base}/model/register",
        headers=headers,
        json=payload,
        timeout=self.http_timeout,
        allow_redirects=False
      )
    except requests.RequestException as e:
      self.logger.error("Network error during model registration", exc_info=e)
      raise RegistrationError("Network error during model registration")

    if resp.status_code != 200:
      self.logger.warning("Model registration failed", extra={"status": resp.status_code})
      raise RegistrationError(f"Model registration failed ({resp.status_code}): {resp.json().get("error")}")

    self.logger.info("Model '%s' registered for provider '%s'", name, provider)
    return resp.json()

  def get_user_details(self) -> UserResp:
    """
    Retrieve info about the authenticated user.
    """
    token = self.token()
    headers = {"Authorization": f"Bearer {token}"}
    resp = self._http_session.get(
      f"{self.proxy_base}/auth/me",
      headers=headers,
      timeout=self.http_timeout,
      allow_redirects=False
    )
    try:
      resp.raise_for_status()
    except requests.HTTPError:
      self.logger.error("Failed to fetch user details: %s", resp.text)
      raise

    user = UserResp(**resp.json())
    return user

  def _refresh(self, force: bool = False):
    """
    Refresh proxy access token if near expiry.
    """
    with self._lock:
      if time.time() < self._session.expires_at - 60 and not force:
        return
      try:
        payload = RefreshReq(refresh_token=self._session.refresh_token).model_dump(mode="json")
        headers = {"Authorization": f"Bearer {self._session.access_token}"}
        resp = self._http_session.post(
          f"{self.proxy_base}/auth/refresh",
          json=payload,
          headers=headers,
          timeout=self.http_timeout,
          allow_redirects=False
        )
      except requests.RequestException as e:
        self.logger.error("Network error during token refresh", exc_info=e)
        raise RefreshError("Network error during token refresh")

      if resp.status_code != 200:
        self.logger.warning("Token refresh failed", extra={"status": resp.status_code})
        raise RefreshError(f"Token refresh failed ({resp.status_code}): {resp.json().get("error")}")

      self._session = AuthResp(**resp.json())
      self.logger.debug("Access token refreshed; expiry=%s", self._session.expires_at)

  def token(self) -> str:
    """
    Return a valid proxy access token, refreshing if necessary.
    """
    if time.time() > self._session.expires_at - 60:
      self._refresh()
    return self._session.access_token

  def api_url(self) -> str:
    """
    Return the proxy API base URL (/v1).
    """
    return self.proxy_api_url
