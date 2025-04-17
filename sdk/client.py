import os, time, threading, logging
import jwt, requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

from .utils import get_provider_url
from .models import (
  ProxyConfig, LoginReq, LoginResp, SwapReq, SwapResp,
  RefreshReq, RefreshResp, RegisterModelReq
)
from .exceptions import (
  AuthenticationError, RefreshError, RegistrationError
)

class Covalence:
  def __init__(self, **config_kwargs):
    self.config = ProxyConfig(**config_kwargs)
    self.logger = logging.getLogger(__name__)

    # pick up any provider key from env
    env_key = os.getenv(f"{self.config.provider.upper()}_API_KEY")
    self.raw_key = env_key

    # prepare HTTP session w/ retries
    self._session = requests.Session()
    self._mount_retries()
    self._lock = threading.Lock()

    # auth flow
    self._login()
    self._swap_key()

  def _mount_retries(self):
    strat = Retry(total=3, backoff_factor=0.3, status_forcelist=[502,503,504])
    adapter = HTTPAdapter(max_retries=strat)
    self._session.mount("https://", adapter)
    self._session.mount("http://",  adapter)

  def _login(self):
    req = LoginReq(
      email=self.config.email,
      password=self.config.password
    )
    url = f"{self.config.proxy_url}/auth/login"
    r = self._session.post(url, json=req.dict())
    if r.status_code != 200:
      raise AuthenticationError(f"Login failed ({r.status_code}): {r.text}")
    self._session_jwt = LoginResp(**r.json()).access_token
    self.logger.debug("✅ Logged in")

  def _swap_key(self):
    key = self.raw_key or input(f"Enter {self.config.provider} API key: ").strip()
    req = SwapReq(provider=self.config.provider, api_key=key)
    url = f"{self.config.proxy_url}/auth/token"
    hdr = {"Authorization":f"Bearer {self._session_jwt}"}
    r = self._session.post(url, headers=hdr, json=req.dict())
    if r.status_code != 200:
      raise AuthenticationError(f"Swap failed ({r.status_code}): {r.text}")
    sr = SwapResp(**r.json())
    self._access_token, self._refresh_token = sr.access_token, sr.refresh_token
    # decode expiry
    claims = jwt.decode(self._access_token, options={"verify_signature":False})
    self._expiry = claims.get("exp",0)
    self.logger.debug("🔑 Key swapped")

  def _refresh(self):
    with self._lock:
      if time.time() < self._expiry - 60:
        return
      req = RefreshReq(refresh_token=self._refresh_token)
      url = f"{self.config.proxy_url}/auth/refresh"
      r = self._session.post(url, json=req.dict())
      if r.status_code != 200:
        raise RefreshError(f"Refresh failed ({r.status_code}): {r.text}")
      self._access_token = RefreshResp(**r.json()).access_token
      claims = jwt.decode(self._access_token, options={"verify_signature":False})
      self._expiry = claims.get("exp",0)
      self.logger.debug("🔄 Token refreshed")

  def register_model(
    self, name:str, model:str,
    provider: str|None=None,
    custom_api_url: str|None=None
  ) -> dict:
    prov   = provider or self.config.provider
    api_url = custom_api_url or get_provider_url(prov)
    req = RegisterModelReq(
      name=name, model=model,
      provider=prov, api_url=api_url
    )
    url = f"{self.config.proxy_url}/model/register"
    hdr = {"Authorization":f"Bearer {self._access_token}"}
    r = self._session.post(url, headers=hdr, json=req.dict())
    if r.status_code != 200:
      raise RegistrationError(f"Register failed ({r.status_code}): {r.text}")
    self.logger.info(f"Model '{name}' registered")
    return r.json()

  def get_token(self) -> str:
    if time.time() > self._expiry - 60:
      self._refresh()
    return self._access_token

  def get_headers(self) -> dict:
    return {"Authorization":f"Bearer {self.get_token()}"}
