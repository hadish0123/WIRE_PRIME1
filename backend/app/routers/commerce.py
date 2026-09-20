from datetime import datetime,timezone,timedelta
from fastapi import APIRouter,Depends,HTTPException,Request
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin,require_tenant_manager
from ..models import Admin,Product,Plan,Order,Payment,Client,Subscription
router=APIRouter()
@router.get("/plans")
def plans(admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 return db.query(Plan).join(Product,Plan.product_id==Product.id).filter(Product.tenant_id==admin.tenant_id,Plan.enabled==True).all()
@router.post("/orders")
def create_order(plan_id:str,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 key=request.headers.get("Idempotency-Key")
 if not key:raise HTTPException(400,"Idempotency-Key required")
 old=db.query(Order).filter(Order.idempotency_key==key,Order.tenant_id==admin.tenant_id).first()
 if old:return old
 plan=db.query(Plan).join(Product,Plan.product_id==Product.id).filter(Plan.id==plan_id,Product.tenant_id==admin.tenant_id,Plan.enabled==True).first()
 if not plan:raise HTTPException(404,"Plan not found")
 order=Order(tenant_id=admin.tenant_id,admin_id=admin.id,plan_id=plan.id,idempotency_key=key,total_minor=plan.price_minor,currency=plan.currency);db.add(order);db.commit();db.refresh(order);return order
@router.post("/orders/{order_id}/payment")
def create_payment(order_id:str,provider:str,provider_reference:str,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 order=db.query(Order).filter(Order.id==order_id,Order.tenant_id==admin.tenant_id).first()
 if not order:raise HTTPException(404,"Order not found")
 if order.status=="PAID":return {"status":"already_paid"}
 payment=Payment(order_id=order.id,provider=provider,provider_reference=provider_reference,amount_minor=order.total_minor,currency=order.currency,status="PENDING");db.add(payment);db.commit();db.refresh(payment);return payment
@router.post("/payments/{payment_id}/confirm")
def confirm_payment(payment_id:str,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 payment=db.query(Payment).join(Order,Payment.order_id==Order.id).filter(Payment.id==payment_id,Order.tenant_id==admin.tenant_id).first()
 if not payment:raise HTTPException(404,"Payment not found")
 payment.status="SUCCEEDED";order=db.query(Order).filter(Order.id==payment.order_id).first();order.status="PAID";db.commit()
 return {"status":"paid","order_id":order.id}
@router.post("/subscriptions")
def subscribe(client_id:str,plan_id:str,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 client=db.query(Client).filter(Client.id==client_id,Client.tenant_id==admin.tenant_id).first()
 plan=db.query(Plan).join(Product,Plan.product_id==Product.id).filter(Plan.id==plan_id,Product.tenant_id==admin.tenant_id,Plan.enabled==True).first()
 if not client or not plan:raise HTTPException(404,"Client or plan not found")
 now=datetime.now(timezone.utc);sub=Subscription(tenant_id=admin.tenant_id,client_id=client.id,plan_id=plan.id,starts_at=now,ends_at=now+timedelta(days=plan.duration_days),traffic_bytes=plan.traffic_bytes);db.add(sub);db.commit();db.refresh(sub);return sub
