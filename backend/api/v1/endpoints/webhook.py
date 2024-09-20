import stripe
import json
from fastapi import APIRouter, Request, HTTPException
from config.settings import STRIPE_WEBHOOK_KEY, STRIPE_API_KEY

router = APIRouter()
stripe.api_key = STRIPE_API_KEY
endpoint_secret = STRIPE_WEBHOOK_KEY

@router.post("/webhook")
async def stripe_webhook(request: Request):
  payload = await request.body()
  sig_header = request.headers.get('stripe-signature')
  event = None

  try:
        event = stripe.Webhook.construct_event(
          payload, sig_header, endpoint_secret
        )
  except json.JSONDecodeError:
      raise HTTPException(status_code=400, detail="Invalid payload")
  except stripe.error.SignatureVerificationError:
      raise HTTPException(status_code=400, detail="Invalid signature")

  if event['type'] == 'checkout.session.completed':
      # TODO: Check for duplicate events for security reasons
        event_id = event['id']
        
        if event['data']:
            object_received = event['data']['object']
            session_id = object_received['id']
            user_id = object_received['metadata']['userId']
            scan_id = object_received['metadata']['scanId']
            # TODO: Add above variables to the database    
  return {"success": True}

