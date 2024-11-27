# src/llmguardian/api/routes.py
from fastapi import APIRouter, Depends, HTTPException
from typing import List
from .models import (
    SecurityRequest, SecurityResponse,
    PrivacyRequest, VectorRequest
)
from ..data.privacy_guard import PrivacyGuard
from ..vectors.vector_scanner import VectorScanner
from .security import verify_token

router = APIRouter()

@router.post("/scan", response_model=SecurityResponse)
async def scan_content(
    request: SecurityRequest,
    token: str = Depends(verify_token)
):
    try:
        privacy_guard = PrivacyGuard()
        result = privacy_guard.check_privacy(request.content, request.context)
        return SecurityResponse(**result.__dict__)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/privacy/check")
async def check_privacy(
    request: PrivacyRequest,
    token: str = Depends(verify_token)
):
    try:
        privacy_guard = PrivacyGuard() 
        result = privacy_guard.enforce_privacy(
            request.content,
            request.privacy_level,
            request.context
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/vectors/scan") 
async def scan_vectors(
    request: VectorRequest,
    token: str = Depends(verify_token)
):
    try:
        scanner = VectorScanner()
        result = scanner.scan_vectors(request.vectors, request.metadata)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))