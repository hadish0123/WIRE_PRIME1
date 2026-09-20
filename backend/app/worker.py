import json,time,logging
from datetime import datetime,timezone,timedelta
from sqlalchemy import func,text
from .db import SessionLocal,set_platform_context
from .models import Job,Quota,TrafficUsage,Device,Client,Inbound,ClientCredential,Protocol,Node,NodeState,InboundOpenVPN,NodePeerCounter,ResourceState,Session
from .services import agent_client
from .services.reconcile import sync_node
from .services.openvpn_revoke import revoke_certificate
from .security import decrypt_secret

log=logging.getLogger("primevpn.worker")
logging.basicConfig(level=logging.INFO)

def collect_traffic(db):
    for node in db.query(Node).filter(Node.agent_url.isnot(None),Node.state.notin_([NodeState.quarantined,NodeState.provision_failed])).all():
        for inbound in db.query(Inbound).filter(Inbound.node_id==node.id,Inbound.tenant_id==node.tenant_id).all():
            try:
                kind="wireguard" if inbound.protocol in {Protocol.wireguard,Protocol.amneziawg} else "openvpn"
                data=agent_client.call(node,"GET",f"counters/{kind}/{inbound.interface}")
                if kind=="wireguard":
                    rows=data.get("peers",[])
                    for peer in rows:
                        cred=db.query(ClientCredential).filter(ClientCredential.public_identifier==peer["public_key"],ClientCredential.revoked_at.is_(None)).first()
                        if not cred: continue
                        client=db.query(Client).filter(Client.id==cred.client_id,Client.tenant_id==node.tenant_id).first()
                        if not client: continue
                        identifier=peer["public_key"];cur_in=int(peer["bytes_received"]);cur_out=int(peer["bytes_sent"])
                        previous=db.query(NodePeerCounter).filter_by(node_id=node.id,inbound_id=inbound.id,public_identifier=identifier).first()
                        old_in=previous.bytes_in if previous else 0;old_out=previous.bytes_out if previous else 0
                        di=max(0,cur_in-old_in);do=max(0,cur_out-old_out)
                        handshake=int(peer.get("last_handshake") or 0)
                        active=handshake>0 and int(time.time())-handshake<180
                        sess=db.query(Session).filter(Session.client_id==client.id,Session.node_id==node.id,Session.inbound_id==inbound.id,Session.ended_at.is_(None)).order_by(Session.started_at.desc()).first()
                        if active and not sess:sess=Session(tenant_id=client.tenant_id,client_id=client.id,node_id=node.id,inbound_id=inbound.id,endpoint=peer.get("endpoint"),bytes_in=cur_in,bytes_out=cur_out);db.add(sess)
                        elif active and sess:sess.endpoint=peer.get("endpoint");sess.bytes_in=cur_in;sess.bytes_out=cur_out;sess.last_seen_at=datetime.now(timezone.utc)
                        elif sess:sess.ended_at=datetime.now(timezone.utc)
                        if di or do: db.add(TrafficUsage(tenant_id=client.tenant_id,client_id=client.id,node_id=node.id,inbound_id=inbound.id,bytes_in=di,bytes_out=do))
                        if not previous: previous=NodePeerCounter(tenant_id=client.tenant_id,node_id=node.id,inbound_id=inbound.id,client_id=client.id,public_identifier=identifier)
                        previous.bytes_in=cur_in;previous.bytes_out=cur_out;db.add(previous)
                else:
                    seen_clients=set()
                    for peer in data.get("clients",[]):
                        client=db.query(Client).filter(Client.name==peer["common_name"],Client.tenant_id==node.tenant_id,Client.inbound_id==inbound.id).first()
                        if not client: continue
                        seen_clients.add(client.id)
                        identifier=peer["common_name"];cur_in=int(peer["bytes_received"]);cur_out=int(peer["bytes_sent"])
                        previous=db.query(NodePeerCounter).filter_by(node_id=node.id,inbound_id=inbound.id,public_identifier=identifier).first()
                        old_in=previous.bytes_in if previous else 0;old_out=previous.bytes_out if previous else 0
                        di=max(0,cur_in-old_in);do=max(0,cur_out-old_out)
                        sess=db.query(Session).filter(Session.client_id==client.id,Session.node_id==node.id,Session.inbound_id==inbound.id,Session.ended_at.is_(None)).order_by(Session.started_at.desc()).first()
                        if not sess:sess=Session(tenant_id=client.tenant_id,client_id=client.id,node_id=node.id,inbound_id=inbound.id,endpoint=peer.get("real_address"),bytes_in=cur_in,bytes_out=cur_out);db.add(sess)
                        else:sess.endpoint=peer.get("real_address");sess.bytes_in=cur_in;sess.bytes_out=cur_out;sess.last_seen_at=datetime.now(timezone.utc)
                        if di or do: db.add(TrafficUsage(tenant_id=client.tenant_id,client_id=client.id,node_id=node.id,inbound_id=inbound.id,bytes_in=di,bytes_out=do))
                        if not previous: previous=NodePeerCounter(tenant_id=client.tenant_id,node_id=node.id,inbound_id=inbound.id,client_id=client.id,public_identifier=identifier)
                        previous.bytes_in=cur_in;previous.bytes_out=cur_out;db.add(previous)
                    stale=db.query(Session).filter(Session.node_id==node.id,Session.inbound_id==inbound.id,Session.ended_at.is_(None)).all()
                    for sess in stale:
                        if sess.client_id not in seen_clients:sess.ended_at=datetime.now(timezone.utc)
            except Exception as exc:
                node.state=NodeState.degraded
                log.warning("traffic collection failed node=%s inbound=%s: %s",node.id,inbound.id,exc)
        db.commit()

def revoke_client(db,c):
    inbound=db.query(Inbound).filter(Inbound.id==c.inbound_id,Inbound.tenant_id==c.tenant_id).first()
    node=db.query(Node).filter(Node.id==inbound.node_id,Node.tenant_id==c.tenant_id).first() if inbound else None
    creds=db.query(ClientCredential).filter(ClientCredential.client_id==c.id,ClientCredential.revoked_at.is_(None)).order_by(ClientCredential.created_at.desc()).all()
    if not inbound or not node or not node.agent_url or not creds:return
    if inbound.protocol in {Protocol.wireguard,Protocol.amneziawg}:
        for cred in creds:agent_client.revoke_wireguard_peer(node,inbound.interface,cred.public_identifier)
    elif inbound.protocol==Protocol.openvpn:
        ov=db.query(InboundOpenVPN).filter(InboundOpenVPN.inbound_id==inbound.id).first()
        if ov and ov.ca_key_encrypted and ov.ca_pem:
            for cred in creds:
                if not cred.encrypted_private_material:continue
                material=json.loads(decrypt_secret(cred.encrypted_private_material))
                ov.crl_pem=revoke_certificate(ov.crl_pem,material["certificate"],decrypt_secret(ov.ca_key_encrypted),ov.ca_pem)
            agent_client.deploy_openvpn_crl(node,inbound.interface,ov.crl_pem)
    for cred in creds:cred.revoked_at=datetime.now(timezone.utc)

def enforce_quotas(db):
    now=datetime.now(timezone.utc);day=now.replace(hour=0,minute=0,second=0,microsecond=0);month=now.replace(day=1,hour=0,minute=0,second=0)
    for q in db.query(Quota).all():
        def used(since=None):
            query=db.query(func.coalesce(func.sum(TrafficUsage.bytes_in+TrafficUsage.bytes_out),0)).filter(TrafficUsage.client_id==q.client_id,TrafficUsage.tenant_id==q.tenant_id)
            if since: query=query.filter(TrafficUsage.last_seen>=since)
            return int(query.scalar() or 0)
        total,daily,monthly=used(),used(day),used(month)
        devices=int(db.query(func.count(Device.id)).join(ClientCredential,ClientCredential.device_id==Device.id).filter(Device.client_id==q.client_id,Device.tenant_id==q.tenant_id,ClientCredential.revoked_at.is_(None)).scalar() or 0)
        c=db.query(Client).filter(Client.id==q.client_id,Client.tenant_id==q.tenant_id).first()
        if not c: continue
        limited=False
        if q.expires_at and q.expires_at<=now:
            q.state="SUSPENDED";c.status=ResourceState.expired;limited=True
        elif c.expires_at and c.expires_at<=now:
            q.state="SUSPENDED";c.status=ResourceState.expired;limited=True
        elif q.max_devices is not None and devices>q.max_devices:
            q.state="LIMIT_REACHED";c.status=ResourceState.suspended;limited=True
        elif q.daily_bytes is not None and daily>=q.daily_bytes:
            q.state="LIMIT_REACHED";c.status=ResourceState.suspended;limited=True
        elif q.monthly_bytes is not None and monthly>=q.monthly_bytes:
            q.state="LIMIT_REACHED";c.status=ResourceState.suspended;limited=True
        elif q.total_bytes is not None and total>=q.total_bytes:
            q.state="LIMIT_REACHED";c.status=ResourceState.suspended;limited=True
        elif q.total_bytes and total>=q.total_bytes*q.warning_ratio/100:
            q.state="WARNING"
        else:
            q.state="NORMAL"
        elif q.state in {"NORMAL","WARNING"} and c.status==ResourceState.suspended:
            c.status=ResourceState.active
        if limited:
            # Do not permanently revoke credentials for quota limits. Reconciliation removes
            # suspended peers and restores them automatically when a daily/monthly window resets.
            pass
    db.commit()

def run_job(db,j):
    payload=json.loads(j.payload or "{}")
    if j.kind in {"SYNC_NODE","PROVISION_NODE"}:
        node=db.query(Node).filter(Node.id==payload.get("node_id")).first()
        if not node: raise RuntimeError("Node not found")
        sync_node(db,node,agent_client)
    elif j.kind=="REVOKE_CLIENT":
        c=db.query(Client).filter(Client.id==payload.get("client_id")).first()
        if not c: raise RuntimeError("Client not found")
        revoke_client(db,c)
        c.status=ResourceState.revoked
    elif j.kind=="ENFORCE_QUOTA":
        enforce_quotas(db)
    else:
        raise RuntimeError(f"Unsupported job kind: {j.kind}")

def process_jobs(db):
    jobs=db.query(Job).filter(Job.state=="QUEUED",Job.run_after<=datetime.now(timezone.utc)).order_by(Job.run_after).with_for_update(skip_locked=True).limit(20).all()
    for j in jobs:
        j.state="RUNNING";j.attempts+=1
    db.commit()
    for j in jobs:
        try:
            run_job(db,j);j.state="SUCCEEDED";db.commit()
        except Exception as exc:
            db.rollback();j=db.query(Job).filter(Job.id==j.id).first();j.state="FAILED" if j.attempts>=5 else "QUEUED";j.run_after=datetime.now(timezone.utc)+timedelta(seconds=min(300,2**min(j.attempts,8)))
            db.commit();log.error("job failed id=%s kind=%s attempt=%s: %s",j.id,j.kind,j.attempts,exc)

def run_once():
    db=SessionLocal()
    try:
        set_platform_context(db)
        collect_traffic(db)
        enforce_quotas(db)
        for node in db.query(Node).filter(Node.agent_url.isnot(None),Node.state.notin_([NodeState.quarantined,NodeState.provision_failed])).all():
            try: sync_node(db,node,agent_client);db.commit()
            except Exception as exc:
                db.rollback();node=db.query(Node).filter(Node.id==node.id).first() if node else None
                if node: node.state=NodeState.degraded;db.commit()
                log.warning("node reconciliation failed: %s",exc)
        process_jobs(db)
    finally:
        db.close()

if __name__=="__main__":
    while True:
        try: run_once()
        except Exception: log.exception("worker cycle failed")
        time.sleep(10)
