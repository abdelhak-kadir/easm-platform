"""Shared helpers for the WHOIS tool's scan/parse modules."""

from datetime import UTC, datetime


def to_aware(dt: datetime) -> datetime:
    """Some registrars return naive datetimes -- assume UTC so they can
    be safely compared/diffed against an aware `datetime.now(UTC)`."""
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
