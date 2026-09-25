"""API_Login — login token endpoint (DRAFT).

Response fields mirror Response_GetLoginToken static evidence
(TASK-006-result.md section 3.4).
"""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class LoginResponse(BaseModel):
    Status: int = 0
    UserId: str = ""
    Token: str = ""
    Desc: str = ""
    First: int = 0
    method: str = ""
    BindFacebook: int = 0
    BindGoogle: int = 0
    BindGameCenter: int = 0
    RealName: int = 0
    FCMStatus: int = 0
    logout_ex_time: int = 0


@router.post("/login")
async def login() -> LoginResponse:
    # TODO: confirm actual URL path + V4_POST_Login params + Sign() (TASK-007)
    return LoginResponse(Desc="DRAFT - not for client use")
