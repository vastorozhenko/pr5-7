from typing import Optional
from pydantic import BaseModel, Field

USERNAME = Field(min_length=3, max_length=32, pattern=r'^[a-z0-9_.-]+$')


class EchoIn(BaseModel):
    msg: str = Field(min_length=1, max_length=1024)


class LoginIn(BaseModel):
    username: str = USERNAME
    password: str = Field(min_length=1, max_length=128)
    otp: Optional[str] = Field(default=None, pattern=r'^\d{6}$')


class OtpIn(BaseModel):
    otp: str = Field(pattern=r'^\d{6}$')


class TokenOut(BaseModel):
    access_token: str
    token_type: str = 'bearer'
    expires_in: int
