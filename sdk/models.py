from typing import Literal
from pydantic import BaseModel, EmailStr, Field, AnyUrl

class ProxyConfig(BaseModel):
  proxy_url: AnyUrl = Field(..., description="Your proxy’s base URL")
  email: EmailStr = Field(..., description="User email for login")
  password: str = Field(..., description="User password for login")
  provider: Literal["openai","cohere","anthropic","gemini"] = Field(
    "openai", description="Default provider for registration"
  )
  custom_api_url: AnyUrl | None = Field(
    None, description="Override provider URL if needed"
  )

class LoginReq(BaseModel):
  email: EmailStr
  password: str

class LoginResp(BaseModel):
  access_token: str

class SwapReq(BaseModel):
  provider: Literal["openai","cohere","anthropic","gemini"]
  api_key: str

class SwapResp(BaseModel):
  access_token:  str
  refresh_token: str

class RefreshReq(BaseModel):
  refresh_token: str

class RefreshResp(BaseModel):
  access_token: str

class RegisterModelReq(BaseModel):
  name: str
  model: str
  provider: Literal["openai","cohere","anthropic","gemini"]
  api_url: AnyUrl