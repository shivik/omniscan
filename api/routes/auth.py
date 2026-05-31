from __future__ import annotations

from fastapi import APIRouter

from api.deps import SessionDep
from api.schemas.models import TokenRequest, TokenResponse
from core.ids import new_id
from core.models import User
from core.security import Principal, issue_token

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/token", response_model=TokenResponse)
async def create_token(body: TokenRequest, session: SessionDep) -> TokenResponse:
    """Dev token issuance. Prod integrates an IdP / signed tokens."""
    user = User(id=new_id("user"), email=body.email, role=body.role)
    session.add(user)
    await session.flush()
    token = new_id("tok")
    issue_token(token, Principal(user_id=user.id, email=user.email, role=body.role))
    return TokenResponse(token=token, user_id=user.id, role=body.role)
