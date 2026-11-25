"""MCAS core schema for PostgreSQL 16 (SQLAlchemy 2.0 async).

Maps the existing SQLite tables from backend/app.py init_db(), keeping table and
column names so queries port 1:1, and adds new pieces (token_version, MFA,
Subscription, idempotent ledger, AsyncJob) as marked extensions.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Identity,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )


def _user_fk(ondelete: str = "CASCADE", nullable: bool = False) -> Mapped[uuid.UUID]:
    return mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete=ondelete),
        nullable=nullable,
    )


def _ts(nullable: bool = False, auto: bool = True, onupdate: bool = False) -> Mapped[datetime]:
    kwargs: dict[str, Any] = {"nullable": nullable}
    if auto:
        kwargs.update(default=utcnow, server_default=func.now())
    if onupdate:
        kwargs["onupdate"] = utcnow
    return mapped_column(DateTime(timezone=True), **kwargs)


def _enum(enum_cls: type[enum.Enum], name: str, length: int = 20) -> SAEnum:
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=length,
        values_callable=lambda e: [m.value for m in e],
        validate_strings=True,
    )


class SubscriptionStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    PAST_DUE = "PAST_DUE"
    CANCELED = "CANCELED"


class BillingCurrency(str, enum.Enum):
    USD = "USD"
    KES = "KES"


class LedgerStatus(str, enum.Enum):
    RESERVED = "RESERVED"
    COMMITTED = "COMMITTED"
    REFUNDED = "REFUNDED"
    ADMIN_BYPASS = "ADMIN_BYPASS"


class JobStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


# --------------------------------------------------------------------------- #
# Identity and sessions
# --------------------------------------------------------------------------- #

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = _uuid_pk()
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = _ts(onupdate=True)
    google_subject: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # New extensions
    is_verified: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    is_admin: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    token_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    __table_args__ = (
        CheckConstraint("email = lower(email)", name="email_lowercase"),
        CheckConstraint("token_version >= 0", name="token_version_non_negative"),
        CheckConstraint("(NOT mfa_enabled) OR (mfa_secret IS NOT NULL)", name="mfa_requires_secret"),
        Index(
            "uq_users_google_subject",
            "google_subject",
            unique=True,
            postgresql_where=text("google_subject IS NOT NULL"),
        ),
    )


class Session(Base):
    __tablename__ = "sessions"

    token_hash: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[uuid.UUID] = _user_fk("CASCADE")
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    token_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )

    __table_args__ = (
        Index("idx_sessions_expiry", "expires_at"),
        Index("ix_sessions_user_id", "user_id"),
    )


class SecurityRateLimit(Base):
    __tablename__ = "security_rate_limits"

    bucket_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    window_start: Mapped[int] = mapped_column(BigInteger, nullable=False)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False)


class GoogleAuthNonce(Base):
    __tablename__ = "google_auth_nonces"

    nonce_hash: Mapped[str] = mapped_column(String(128), primary_key=True)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class OAuthState(Base):
    __tablename__ = "oauth_states"

    state_hash: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[uuid.UUID] = _user_fk("CASCADE")
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)

    __table_args__ = (Index("ix_oauth_states_user_id", "user_id"),)


class Integration(Base):
    __tablename__ = "integrations"

    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    provider: Mapped[str] = mapped_column(String(64), primary_key=True)
    encrypted_refresh_token: Mapped[str] = mapped_column(Text, nullable=False)
    connected_at: Mapped[datetime] = _ts()


class WorkspacePreference(Base):
    __tablename__ = "workspace_preferences"

    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    country_code: Mapped[str] = mapped_column(String(8), nullable=False, server_default="KE")
    currency_code: Mapped[str] = mapped_column(String(8), nullable=False, server_default="KES")
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, server_default="auto")
    language_code: Mapped[str] = mapped_column(String(16), nullable=False, server_default="en")
    theme: Mapped[str] = mapped_column(String(16), nullable=False, server_default="dark")
    pricing_multiplier: Mapped[float] = mapped_column(Float, nullable=False, server_default=text("1.0"))
    updated_at: Mapped[datetime] = _ts(onupdate=True)


# --------------------------------------------------------------------------- #
# Prospecting workspace
# --------------------------------------------------------------------------- #

class Lead(Base):
    __tablename__ = "leads"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = _user_fk("CASCADE")
    name: Mapped[str] = mapped_column(Text, nullable=False)
    website: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    market: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default="Unverified")
    score: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = _ts(onupdate=True)

    __table_args__ = (Index("idx_leads_user_updated", "user_id", "updated_at"),)


class Draft(Base):
    __tablename__ = "drafts"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = _user_fk("CASCADE")
    lead_id: Mapped[Optional[uuid.UUID]] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, server_default="pending_approval")
    created_at: Mapped[datetime] = _ts()

    __table_args__ = (Index("idx_drafts_user_created", "user_id", "created_at"),)


class Followup(Base):
    __tablename__ = "followups"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = _user_fk("CASCADE")
    lead_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("leads.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    due_at: Mapped[Optional[datetime]] = _ts(nullable=True, auto=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, server_default="open")
    notes: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    created_at: Mapped[datetime] = _ts()

    __table_args__ = (Index("idx_followups_user_due", "user_id", "due_at", "state"),)


class Proposal(Base):
    __tablename__ = "proposals"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = _user_fk("CASCADE")
    lead_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("leads.id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, server_default="draft")
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = _ts(onupdate=True)

    __table_args__ = (Index("idx_proposals_user", "user_id", "updated_at"),)


class WebsiteAuditReport(Base):
    __tablename__ = "website_audit_reports"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = _user_fk("CASCADE")
    lead_id: Mapped[Optional[uuid.UUID]] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    website_url: Mapped[str] = mapped_column(Text, nullable=False)
    report_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = _ts()

    __table_args__ = (Index("idx_audit_reports_user_created", "user_id", "created_at"),)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=False), primary_key=True)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = _ts()
    meta: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (
        Index("ix_audit_log_user_id_created_at", "user_id", "created_at"),
        Index("ix_audit_log_action_created_at", "action", "created_at"),
    )


# --------------------------------------------------------------------------- #
# Feedback and improvement centre
# --------------------------------------------------------------------------- #

class CustomerFeedback(Base):
    __tablename__ = "customer_feedback"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = _user_fk("CASCADE")
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default="received")
    admin_note: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = _ts(onupdate=True)

    __table_args__ = (
        Index("idx_feedback_user_created", "user_id", "created_at"),
        Index("idx_feedback_status_created", "status", "created_at"),
    )


class ImprovementReview(Base):
    __tablename__ = "improvement_reviews"

    id: Mapped[uuid.UUID] = _uuid_pk()
    created_by: Mapped[uuid.UUID] = _user_fk("RESTRICT")
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    recommendations_json: Mapped[Any] = mapped_column(JSONB, nullable=False)
    feedback_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = _ts()

    __table_args__ = (Index("ix_improvement_reviews_created_by", "created_by"),)


class ImprovementReviewFeedback(Base):
    __tablename__ = "improvement_review_feedback"

    review_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("improvement_reviews.id", ondelete="CASCADE"),
        primary_key=True,
    )
    feedback_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("customer_feedback.id", ondelete="CASCADE"),
        primary_key=True,
    )


# --------------------------------------------------------------------------- #
# Billing (existing tables)
# --------------------------------------------------------------------------- #

class BillingAccount(Base):
    __tablename__ = "billing_accounts"

    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    plan_code: Mapped[str] = mapped_column(String(64), nullable=False, server_default="free")
    monthly_credits: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("20"))
    purchased_credits: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    period_start: Mapped[Optional[datetime]] = _ts(nullable=True, auto=False)
    period_end: Mapped[Optional[datetime]] = _ts(nullable=True, auto=False)
    updated_at: Mapped[datetime] = _ts(onupdate=True)

    __table_args__ = (
        CheckConstraint("monthly_credits >= 0", name="monthly_credits_non_negative"),
        CheckConstraint("purchased_credits >= 0", name="purchased_credits_non_negative"),
    )


class BillingOrder(Base):
    """tx_ref and provider_transaction_id are UNIQUE: this makes grants idempotent."""

    __tablename__ = "billing_orders"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = _user_fk("RESTRICT")
    tx_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    item_type: Mapped[str] = mapped_column(String(16), nullable=False)
    item_code: Mapped[str] = mapped_column(String(64), nullable=False)
    amount_kes: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, server_default="KES")
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default="pending")
    checkout_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    provider_transaction_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = _ts(onupdate=True)

    __table_args__ = (
        UniqueConstraint("tx_ref", name="uq_billing_orders_tx_ref"),
        UniqueConstraint("provider_transaction_id", name="uq_billing_orders_provider_transaction_id"),
        CheckConstraint("item_type IN ('subscription','credits')", name="item_type_valid"),
        CheckConstraint("amount_kes >= 0", name="amount_non_negative"),
        Index("idx_billing_orders_user_created", "user_id", "created_at"),
    )


class BillingWebhookEvent(Base):
    """Webhook de-duplication: INSERT ... ON CONFLICT DO NOTHING on event_key."""

    __tablename__ = "billing_webhook_events"

    event_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    received_at: Mapped[datetime] = _ts()
    outcome: Mapped[str] = mapped_column(String(64), nullable=False)


class BillingCreditLedger(Base):
    """Existing ledger plus idempotency/status extensions. idempotency_key is
    nullable so legacy rows load; Postgres UNIQUE ignores NULLs."""

    __tablename__ = "billing_credit_ledger"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = _user_fk("RESTRICT")
    delta_monthly: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    delta_purchased: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    reason: Mapped[str] = mapped_column(String(128), nullable=False)
    reference: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = _ts()

    # New extensions
    idempotency_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    status: Mapped[LedgerStatus] = mapped_column(
        _enum(LedgerStatus, "ledger_status"),
        nullable=False,
        default=LedgerStatus.COMMITTED,
        server_default=LedgerStatus.COMMITTED.value,
    )
    settled_at: Mapped[Optional[datetime]] = _ts(nullable=True, auto=False)

    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_billing_credit_ledger_idempotency_key"),
        CheckConstraint(
            "idempotency_key IS NULL OR length(idempotency_key) > 0",
            name="idempotency_key_not_empty",
        ),
        Index("idx_billing_ledger_user_created", "user_id", "created_at"),
        Index("ix_billing_credit_ledger_user_id_status", "user_id", "status"),
        Index("ix_billing_credit_ledger_reference", "reference"),
    )


# --------------------------------------------------------------------------- #
# New tables
# --------------------------------------------------------------------------- #

class Subscription(Base):
    """Dual-currency subscription (new). Minor-unit price snapshots."""

    __tablename__ = "subscriptions"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = _user_fk("RESTRICT")
    plan_code: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[SubscriptionStatus] = mapped_column(
        _enum(SubscriptionStatus, "subscription_status"),
        nullable=False,
        default=SubscriptionStatus.ACTIVE,
        server_default=SubscriptionStatus.ACTIVE.value,
    )
    billing_currency: Mapped[BillingCurrency] = mapped_column(
        _enum(BillingCurrency, "billing_currency", length=3), nullable=False
    )
    price_usd_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    price_kes_cents: Mapped[int] = mapped_column(BigInteger, nullable=False)
    current_period_start: Mapped[datetime] = _ts()
    current_period_end: Mapped[datetime] = _ts(auto=False)
    cancel_at_period_end: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    canceled_at: Mapped[Optional[datetime]] = _ts(nullable=True, auto=False)
    provider: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    provider_subscription_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = _ts(onupdate=True)

    __table_args__ = (
        CheckConstraint("price_usd_cents >= 0 AND price_kes_cents >= 0", name="price_non_negative"),
        CheckConstraint("current_period_end > current_period_start", name="period_ordering"),
        Index("ix_subscriptions_user_id_status", "user_id", "status"),
        Index("ix_subscriptions_status_current_period_end", "status", "current_period_end"),
        Index(
            "uq_subscriptions_one_active_per_user",
            "user_id",
            unique=True,
            postgresql_where=text("status = 'ACTIVE'"),
        ),
        Index(
            "uq_subscriptions_provider_subscription_id",
            "provider",
            "provider_subscription_id",
            unique=True,
            postgresql_where=text("provider_subscription_id IS NOT NULL"),
        ),
    )


class AsyncJob(Base):
    """Durable job queue. Claim with SELECT ... WHERE status='QUEUED'
    ORDER BY created_at FOR UPDATE SKIP LOCKED."""

    __tablename__ = "async_jobs"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = _user_fk("CASCADE")
    credit_ledger_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("billing_credit_ledger.id", ondelete="SET NULL"),
        nullable=True,
    )
    job_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[JobStatus] = mapped_column(
        _enum(JobStatus, "job_status"),
        nullable=False,
        default=JobStatus.QUEUED,
        server_default=JobStatus.QUEUED.value,
    )
    payload_json: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    result_json: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    started_at: Mapped[Optional[datetime]] = _ts(nullable=True, auto=False)
    finished_at: Mapped[Optional[datetime]] = _ts(nullable=True, auto=False)
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = _ts(onupdate=True)

    __table_args__ = (
        CheckConstraint("attempts >= 0", name="attempts_non_negative"),
        Index("ix_async_jobs_user_id_status_created_at", "user_id", "status", "created_at"),
        Index("ix_async_jobs_queue", "created_at", postgresql_where=text("status = 'QUEUED'")),
        Index("ix_async_jobs_job_type_status", "job_type", "status"),
    )
