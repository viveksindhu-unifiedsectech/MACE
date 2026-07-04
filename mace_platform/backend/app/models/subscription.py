"""Stripe-backed subscription + usage metering."""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Boolean, JSON, Float, Integer, Enum as SAEnum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base
import enum


class SubscriptionStatus(str, enum.Enum):
    TRIALING   = "trialing"
    ACTIVE     = "active"
    PAST_DUE   = "past_due"
    CANCELED   = "canceled"
    UNPAID     = "unpaid"
    PAUSED     = "paused"


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)

    # Stripe
    stripe_subscription_id: Mapped[str] = mapped_column(String(255), nullable=True, unique=True)
    stripe_price_id: Mapped[str] = mapped_column(String(255), nullable=True)
    stripe_product_id: Mapped[str] = mapped_column(String(255), nullable=True)

    # Plan details
    plan_name: Mapped[str] = mapped_column(String(100), nullable=False)   # msme | starter | professional | enterprise
    status: Mapped[SubscriptionStatus] = mapped_column(SAEnum(SubscriptionStatus), default=SubscriptionStatus.TRIALING)
    asset_limit: Mapped[int] = mapped_column(Integer, default=500)
    price_per_asset_usd: Mapped[float] = mapped_column(Float, nullable=True)

    # Billing period
    current_period_start: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    current_period_end: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    trial_end: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    canceled_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Metered usage (reset each billing period)
    assets_used: Mapped[int] = mapped_column(Integer, default=0)
    api_calls_used: Mapped[int] = mapped_column(Integer, default=0)
    incidents_this_period: Mapped[int] = mapped_column(Integer, default=0)

    # Invoice settings
    invoice_email: Mapped[str] = mapped_column(String(255), nullable=True)
    po_number: Mapped[str] = mapped_column(String(100), nullable=True)
    tax_id: Mapped[str] = mapped_column(String(100), nullable=True)

    # Features enabled for this subscription
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    # e.g. {"fedramp": true, "govcloud": true, "connectors": ["crowdstrike", "tenable"]}

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="subscriptions")
    usage_records: Mapped[list["UsageRecord"]] = relationship("UsageRecord", back_populates="subscription")


class UsageRecord(Base):
    """Hourly usage snapshots for metered billing."""
    __tablename__ = "usage_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    subscription_id: Mapped[str] = mapped_column(String(36), ForeignKey("subscriptions.id"), nullable=False)

    metric: Mapped[str] = mapped_column(String(100), nullable=False)   # "assets" | "api_calls" | "incidents"
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    stripe_usage_record_id: Mapped[str] = mapped_column(String(255), nullable=True)

    subscription: Mapped["Subscription"] = relationship("Subscription", back_populates="usage_records")
