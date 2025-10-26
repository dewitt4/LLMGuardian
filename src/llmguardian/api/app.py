# src/llmguardian/api/app.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes import router
from .security import SecurityMiddleware

app = FastAPI(
    title="LLMGuardian API",
    description="Security API for LLM applications",
    version="1.0.0",
)

# Security middleware
app.add_middleware(SecurityMiddleware)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")
