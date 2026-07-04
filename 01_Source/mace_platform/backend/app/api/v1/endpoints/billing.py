"""Stripe billing endpoints — subscriptions, usage, invoices, webhooks."""
from fastapi import APIRouter, Depends, HTTPException, Request, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from app.db.base import get_db
from app.auth.dependencies import get_admin, CurrentUser
from app.models.subscription import Subscription, SubscriptionStatus
from app.models.tenant import Tenant, TenantPlan
from app.core.config import settings
import json

router = APIRouter(prefix="/billing", tags=["Billing"])


@router.get("/subscription")
async def get_subscription(
    current: CurrentUser = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Subscription).where(Subscription.tenant_id == current.tenant_id)
        .order_by(Subscription.created_at.desc()).limit(1)
    )
    sub = result.scalar_one_or_none()
    if not sub:
        return {
            "status": "no_subscription",
            "plan": current.tenant.plan.value,
            "trial_ends_at": current.tenant.trial_ends_at.isoformat() if current.tenant.trial_ends_at else None,
        }
    return {
        "id": sub.id,
        "plan_name": sub.plan_name,
        "status": sub.status.value,
        "asset_limit": sub.asset_limit,
        "assets_used": sub.assets_used,
        "price_per_asset_usd": sub.price_per_asset_usd,
        "current_period_start": sub.current_period_start.isoformat() if sub.current_period_start else None,
        "current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None,
        "trial_end": sub.trial_end.isoformat() if sub.trial_end else None,
        "features": sub.features,
    }


@router.post("/create-checkout-session")
async def create_checkout(
    plan: str,                   # starter | professional | enterprise
    jurisdiction: str = "US",
    current: CurrentUser = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
):
    """Create Stripe checkout session for subscription upgrade."""
    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(503, "Billing not configured")

    try:
        import stripe
        stripe.api_key = settings.STRIPE_SECRET_KEY

        price_map = {
            "starter": settings.STRIPE_PRICE_ID_STARTER,
            "professional": settings.STRIPE_PRICE_ID_PROFESSIONAL,
            "enterprise": settings.STRIPE_PRICE_ID_ENTERPRISE,
        }
        price_id = price_map.get(plan)
        if not price_id:
            raise HTTPException(400, f"Unknown plan: {plan}")

        session = stripe.checkout.Session.create(
            customer_email=current.email,
            mode="subscription",
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            metadata={"tenant_id": current.tenant_id, "plan": plan, "jurisdiction": jurisdiction},
            success_url=f"https://app.unifiedsec.com/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"https://app.unifiedsec.com/billing/cancel",
        )
        return {"checkout_url": session.url, "session_id": session.id}
    except Exception as e:
        raise HTTPException(500, f"Stripe error: {str(e)}")


@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None, alias="stripe-signature"),
    db: AsyncSession = Depends(get_db),
):
    """Handle Stripe webhook events — subscription lifecycle."""
    if not settings.STRIPE_WEBHOOK_SECRET:
        raise HTTPException(503, "Webhook not configured")

    payload = await request.body()

    try:
        import stripe
        stripe.api_key = settings.STRIPE_SECRET_KEY
        event = stripe.Webhook.construct_event(payload, stripe_signature, settings.STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        raise HTTPException(400, f"Webhook error: {str(e)}")

    event_type = event["type"]
    data = event["data"]["object"]

    if event_type == "checkout.session.completed":
        tenant_id = data["metadata"].get("tenant_id")
        plan = data["metadata"].get("plan", "starter")
        tenant = await db.get(Tenant, tenant_id)
        if tenant:
            plan_map = {"starter": TenantPlan.STARTER, "professional": TenantPlan.PROFESSIONAL,
                        "enterprise": TenantPlan.ENTERPRISE}
            tenant.plan = plan_map.get(plan, TenantPlan.STARTER)
            tenant.stripe_customer_id = data.get("customer")

    elif event_type in ["customer.subscription.updated", "customer.subscription.created"]:
        stripe_sub = data
        tenant_id = stripe_sub.get("metadata", {}).get("tenant_id")
        if tenant_id:
            result = await db.execute(
                select(Subscription).where(Subscription.stripe_subscription_id == stripe_sub["id"])
            )
            sub = result.scalar_one_or_none()
            if not sub:
                from datetime import datetime
                sub = Subscription(
                    tenant_id=tenant_id,
                    stripe_subscription_id=stripe_sub["id"],
                    stripe_price_id=stripe_sub["items"]["data"][0]["price"]["id"],
                    plan_name=stripe_sub.get("metadata", {}).get("plan", "starter"),
                )
            sub.status = SubscriptionStatus(stripe_sub["status"])
            from datetime import datetime
            if stripe_sub.get("current_period_start"):
                sub.current_period_start = datetime.utcfromtimestamp(stripe_sub["current_period_start"])
            if stripe_sub.get("current_period_end"):
                sub.current_period_end = datetime.utcfromtimestamp(stripe_sub["current_period_end"])
            db.add(sub)

    elif event_type == "customer.subscription.deleted":
        result = await db.execute(
            select(Subscription).where(Subscription.stripe_subscription_id == data["id"])
        )
        sub = result.scalar_one_or_none()
        if sub:
            sub.status = SubscriptionStatus.CANCELED

    return {"received": True, "event_type": event_type}
