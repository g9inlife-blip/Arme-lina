"""API_Anon — anonymous/guest account endpoint (DRAFT).

Response fields mirror Response_Account_Anon static evidence
(TASK-006-result.md section 3.4).
"""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class AnonResponse(BaseModel):
    Status: int = 0
    RoleId: str = ""
    UserId: str = ""
    Token: str = ""
    Desc: str = ""
    Retail: str = ""
    First: int = 0
    logout_ex_time: int = 0


@router.post("/anon")
async def anon() -> AnonResponse:
    # TODO: confirm actual URL path + V3_POST_Anon params (TASK-007)
    return AnonResponse(Desc="DRAFT - not for client use")
