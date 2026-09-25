"""API_Allin1 — bootstrap endpoint (DRAFT).

Response fields mirror Response_Allin1 static evidence
(TASK-006-result.md section 3.5). Values are placeholders until
real contract values are confirmed.
"""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class AllIn1Server(BaseModel):
    Host: str = ""
    Port: int = 8000


class AllIn1Response(BaseModel):
    Status: int = 0
    NoticeStatus: int = 0
    NoticeTime: str = ""
    IP: str = ""
    IsUpgrade: int = 0
    Assets: str = ""
    Keys: str = ""
    Servers: list[AllIn1Server] = []
    Http_API_URL: str = ""
    AssetVersion: str = ""
    BestCDN: str = ""
    Desc: str = ""


@router.post("/allin1")
async def allin1() -> AllIn1Response:
    # TODO: confirm actual URL path + required request params (TASK-007)
    return AllIn1Response(
        Servers=[AllIn1Server(Host="127.0.0.1", Port=8000)],
        Desc="DRAFT - not for client use",
    )
