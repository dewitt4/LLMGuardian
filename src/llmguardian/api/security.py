# src/llmguardian/api/security.py
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

security = HTTPBearer()


class SecurityMiddleware:
    def __init__(
        self, secret_key: str = "your-256-bit-secret", algorithm: str = "HS256"
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm

    async def create_token(self, data: dict, expires_delta: Optional[timedelta] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    async def verify_token(
        self, credentials: HTTPAuthorizationCredentials = Security(security)
    ):
        try:
            payload = jwt.decode(
                credentials.credentials, self.secret_key, algorithms=[self.algorithm]
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.JWTError:
            raise HTTPException(
                status_code=401, detail="Could not validate credentials"
            )


verify_token = SecurityMiddleware().verify_token
