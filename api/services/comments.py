"""Threaded comments on findings — Markdown, @mentions, edit/delete by author."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.services import audit
from core.models import Comment, Finding


async def add(
    session: AsyncSession,
    *,
    finding_id: str,
    author_id: str,
    body: str,
    parent_id: str | None,
    mentions: list[str],
) -> Comment:
    if await session.get(Finding, finding_id) is None:
        raise ValueError(f"unknown finding: {finding_id}")
    comment = Comment(
        finding_id=finding_id,
        author_id=author_id,
        body=body,
        parent_id=parent_id,
        mentions=mentions,
    )
    session.add(comment)
    await session.flush()
    await audit.record(
        session,
        actor_id=author_id,
        action="comment",
        resource_type="finding",
        resource_id=finding_id,
        detail={"comment_id": comment.id, "mentions": mentions},
    )
    # @mentions would notify via the webhooks/notifications channel here.
    return comment


async def list_for_finding(session: AsyncSession, finding_id: str) -> list[Comment]:
    return list(
        await session.scalars(
            select(Comment)
            .where(Comment.finding_id == finding_id)
            .order_by(Comment.created_at.asc())
        )
    )


async def edit(session: AsyncSession, *, comment_id: str, actor_id: str, body: str) -> Comment:
    comment = await session.get(Comment, comment_id)
    if comment is None:
        raise ValueError(f"unknown comment: {comment_id}")
    if comment.author_id != actor_id:
        raise PermissionError("only the author may edit a comment")
    # Edits keep an immutable revision history via the audit log.
    await audit.record(
        session,
        actor_id=actor_id,
        action="comment.edit",
        resource_type="comment",
        resource_id=comment_id,
        detail={"previous_body": comment.body},
    )
    comment.body = body
    comment.edited = True
    return comment


async def delete(session: AsyncSession, *, comment_id: str, actor_id: str) -> Comment:
    comment = await session.get(Comment, comment_id)
    if comment is None:
        raise ValueError(f"unknown comment: {comment_id}")
    if comment.author_id != actor_id:
        raise PermissionError("only the author may delete a comment")
    comment.deleted = True
    comment.body = "[deleted]"
    await audit.record(
        session,
        actor_id=actor_id,
        action="comment.delete",
        resource_type="comment",
        resource_id=comment_id,
    )
    return comment
