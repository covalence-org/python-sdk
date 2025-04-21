from typing import Literal
from pydantic import BaseModel, AnyUrl, EmailStr

class LoginReq(BaseModel):
  email:    EmailStr
  password: str

class LoginResp(BaseModel):
  access_token: str

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
