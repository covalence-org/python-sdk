from typing import Literal
from pydantic import BaseModel, AnyUrl, EmailStr

class AuthReq(BaseModel):
  email:    EmailStr
  password: str

class UserResp(BaseModel):
  id: str
  aud: str
  role: str
  email: EmailStr
  created_at: str
  updated_at: str
  email_confirmed_at: str | None
  phone: str | None

class AuthResp(BaseModel):
  access_token: str
  refresh_token: str
  expires_at:  int
  expires_in: int
  user: UserResp

class SwapReq(BaseModel):
  provider: Literal["openai","cohere","anthropic","gemini"]
  api_key:  str

class SwapResp(BaseModel):
  access_token:  str
  refresh_token: str

class RefreshReq(BaseModel):
  refresh_token: str

class RefreshResp(BaseModel):
  access_token: str

class RegisterModelReq(BaseModel):
  name:     str
  model:    str
  provider: Literal["openai","cohere","anthropic","gemini"]
  api_url:  AnyUrl
