from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from typing import List, Dict
import hashlib
from urllib.parse import quote
from datetime import datetime
import logging

from app.models.payment import PaymentTransaction, Purchase
from app.models.user import User
from app.models.product import Product
from app.db.session import db
from app.services.auth import get_current_user
from app.services.notification import create_notification_helper
from app.services.file import sanitize_filename, get_media_type_for_file
from app.core.config import settings
try:
    from stripe_checkout import StripeCheckout, CheckoutSessionRequest
except ImportError:
    class StripeCheckout:
        def __init__(self, api_key, webhook_url):
            raise NotImplementedError("StripeCheckout class must be implemented or imported from your Stripe integration module.")

    class CheckoutSessionRequest:
        def __init__(self, amount, currency, success_url, cancel_url, metadata):
            pass

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/payments/checkout")
async def create_checkout_session(
    product_id: str,
    request: Request,
    current_user: User = Depends(get_current_user)
):
    # Get product
    product = await db.products.find_one({"id": product_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    # Check if user already owns this product
    existing_purchase = await db.purchases.find_one({
        "buyer_id": current_user.id,
        "product_id": product_id
    })
    if existing_purchase:
        raise HTTPException(status_code=400, detail="Product already purchased")

    # Initialize Stripe
    host_url = str(request.base_url).rstrip('/')
    webhook_url = f"{host_url}/api/webhook/stripe"
    stripe_checkout = StripeCheckout(api_key=settings.STRIPE_API_KEY, webhook_url=webhook_url)

    # Create checkout session
    success_url = f"{host_url}/purchase-success?session_id={{CHECKOUT_SESSION_ID}}&product_id={product_id}"
    cancel_url = f"{host_url}/product/{product_id}"

    checkout_request = CheckoutSessionRequest(
        amount=product["price"],
        currency="usd",
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={
            "product_id": product_id,
            "buyer_id": current_user.id,
            "seller_id": product["seller_id"]
        }
    )

    session = await stripe_checkout.create_checkout_session(checkout_request)

    # Create payment transaction record
    payment_transaction = PaymentTransaction(
        session_id=session.session_id,
        product_id=product_id,
        buyer_id=current_user.id,
        seller_id=product["seller_id"],
        amount=product["price"],
        currency="usd",
        payment_status="pending",
        stripe_status="initiated",
        metadata=checkout_request.metadata
    )

    await db.payment_transactions.insert_one(payment_transaction.dict())

    return {"checkout_url": session.url, "session_id": session.session_id}

@router.get("/payments/status/{session_id}")
async def get_payment_status(session_id: str, current_user: User = Depends(get_current_user)):
    # Get payment transaction
    transaction = await db.payment_transactions.find_one({"session_id": session_id})
    if not transaction:
        raise HTTPException(status_code=404, detail="Payment session not found")

    # Initialize Stripe
    stripe_checkout = StripeCheckout(api_key=settings.STRIPE_API_KEY, webhook_url="")

    # Get checkout status from Stripe
    checkout_status = await stripe_checkout.get_checkout_status(session_id)

    # Update transaction status
    update_data = {
        "stripe_status": checkout_status.status,
        "payment_status": checkout_status.payment_status,
        "updated_at": datetime.utcnow()
    }

    await db.payment_transactions.update_one(
        {"session_id": session_id},
        {"$set": update_data}
    )

    # If payment successful and not already processed, create purchase record
    if checkout_status.payment_status == "paid":
        existing_purchase = await db.purchases.find_one({
            "buyer_id": transaction["buyer_id"],
            "product_id": transaction["product_id"]
        })

        if not existing_purchase:
            # Create download token
            download_token = hashlib.sha256(f"{session_id}{transaction['product_id']}{transaction['buyer_id']}".encode()).hexdigest()

            purchase = Purchase(
                buyer_id=transaction["buyer_id"],
                product_id=transaction["product_id"],
                seller_id=transaction["seller_id"],
                transaction_id=transaction["id"],
                download_token=download_token
            )

            await db.purchases.insert_one(purchase.dict())

            # Get product and user details for notification
            product = await db.products.find_one({"id": transaction["product_id"]})
            buyer = await db.users.find_one({"id": transaction["buyer_id"]})
            seller = await db.users.find_one({"id": transaction["seller_id"]})

            # Create notification for buyer
            if buyer and product:
                await create_notification_helper(
                    user_id=buyer["id"],
                    title="Purchase Successful! 🎉",
                    message=f"You have successfully purchased '{product['title']}'. You can now download it from your purchases page.",
                    notification_type="success",
                    action_url="/my-purchases",
                    metadata={"product_id": product["id"], "product_title": product["title"]}
                )

            # Create notification for seller
            if seller and product:
                await create_notification_helper(
                    user_id=seller["id"],
                    title="New Sale! 💰",
                    message=f"Congratulations! Your product '{product['title']}' has been purchased by {buyer['username']}.",
                    notification_type="success",
                    action_url="/my-products",
                    metadata={"product_id": product["id"], "product_title": product["title"], "buyer_username": buyer["username"]}
                )

            # Update product download count
            await db.products.update_one(
                {"id": transaction["product_id"]},
                {"$inc": {"downloads": 1}}
            )

    return {
        "status": checkout_status.status,
        "payment_status": checkout_status.payment_status,
        "amount_total": checkout_status.amount_total,
        "currency": checkout_status.currency
    }

@router.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    try:
        webhook_request_body = await request.body()
        stripe_signature = request.headers.get("Stripe-Signature")

        if not stripe_signature:
            return {"status": "ok", "message": "No signature provided"}

        stripe_checkout = StripeCheckout(api_key=settings.STRIPE_API_KEY, webhook_url="")
        webhook_response = await stripe_checkout.handle_webhook(webhook_request_body, stripe_signature)

        # Update payment transaction
        if webhook_response.session_id:
            update_data = {
                "stripe_status": webhook_response.event_type,
                "payment_status": webhook_response.payment_status,
                "updated_at": datetime.utcnow()
            }

            await db.payment_transactions.update_one(
                {"session_id": webhook_response.session_id},
                {"$set": update_data}
            )

        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Webhook error: {str(e)}")
        return {"status": "ok", "message": "Webhook processed with errors"}

@router.get("/download/{download_token}")
async def download_file(download_token: str, current_user: User = Depends(get_current_user)):
    # Find purchase by download token
    purchase = await db.purchases.find_one({
        "download_token": download_token,
        "buyer_id": current_user.id
    })

    if not purchase:
        raise HTTPException(status_code=404, detail="Download not found or unauthorized")

    # Get product info
    product = await db.products.find_one({"id": purchase["product_id"]})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    # Get file path
    file_path = settings.UPLOAD_DIR / product["file_name"]
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    # Verify file integrity
    try:
        file_size = file_path.stat().st_size
        if file_size == 0:
            raise HTTPException(status_code=500, detail="File is empty or corrupted")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File access error: {str(e)}")

    # Create safe filename - try using sanitized product title, fallback to original filename
    original_filename = product.get("original_filename", "")
    file_extension = product["file_name"].split('.')[-1].lower()

    # Try to create filename from product title
    if product.get("title"):
        base_filename = f"{product['title']}.{file_extension}"
        safe_filename = sanitize_filename(base_filename)
    else:
        # Fallback to original filename or generic name
        safe_filename = sanitize_filename(original_filename) if original_filename else f"download.{file_extension}"

    # Ensure the safe filename is not empty and has proper extension
    if not safe_filename or safe_filename == "download":
        safe_filename = f"download.{file_extension}"

    # Determine proper media type based on file extension
    media_type = get_media_type_for_file(file_extension)

    # Create FileResponse with proper headers
    response = FileResponse(
        path=file_path,
        filename=safe_filename,
        media_type=media_type
    )

    # Add additional headers for better download handling
    encoded_filename = quote(safe_filename.encode('utf-8'))
    response.headers["Content-Disposition"] = f'attachment; filename="{safe_filename}"; filename*=UTF-8\'\'{encoded_filename}'
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["Content-Length"] = str(file_size)

    return response

@router.get("/my-purchases", response_model=List[Dict])
async def get_my_purchases(current_user: User = Depends(get_current_user)):
    purchases = await db.purchases.find({"buyer_id": current_user.id}).to_list(100)

    result = []
    for purchase in purchases:
        product = await db.products.find_one({"id": purchase["product_id"]})
        if product:
            result.append({
                "purchase": Purchase(**purchase),
                "product": Product(**product)
            })

    return result
