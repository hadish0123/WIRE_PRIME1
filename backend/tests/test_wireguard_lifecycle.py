from datetime import datetime,timedelta,timezone
from types import SimpleNamespace
import subprocess

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db import Base
from app.config import settings
from app.models import (Tenant,Admin,RoleName,Node,NodeState,Inbound,Protocol,
                        InboundWireGuard,Client,ResourceState,Quota,ClientCredential,Device)
from app.security import encrypt_secret
from app.services.credentials import wg_keypair
from app.services.inbound_config import render_inbound
from app.routers import credentials,inbounds,provisioning


@pytest.fixture
def scenario(monkeypatch):
    monkeypatch.setattr(settings,"data_encryption_key",Fernet.generate_key().decode())
    engine=create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine,expire_on_commit=False) as db:
        tenant=Tenant(name="test",slug="test")
        db.add(tenant);db.flush()
        admin=Admin(tenant_id=tenant.id,email="test@example.invalid",password_hash="test",role=RoleName.tenant_manager)
        node=Node(tenant_id=tenant.id,name="new-node",address="109.248.162.41",agent_url="https://109.248.162.41",state=NodeState.ready)
        db.add_all([admin,node]);db.flush()
        inbound=Inbound(tenant_id=tenant.id,node_id=node.id,name="test",protocol=Protocol.wireguard,listen_port=443,interface="wg0",address="10.10.0.1/24",network="10.10.0.0/24")
        db.add(inbound);db.flush()
        private,public=wg_keypair()
        db.add(InboundWireGuard(inbound_id=inbound.id,server_public_key=public,server_private_key_encrypted=encrypt_secret(private)))
        client=Client(tenant_id=tenant.id,created_by_admin_id=admin.id,inbound_id=inbound.id,name="phone",assigned_address="10.10.0.2/32",status=ResourceState.active)
        db.add(client);db.flush()
        db.add(Quota(tenant_id=tenant.id,client_id=client.id,max_devices=1))
        db.commit()
        applies=[]
        def apply(node,protocol,interface,config,files=None):
            applies.append(config)
            return {"applied":True}
        monkeypatch.setattr(credentials,"apply_agent",apply)
        monkeypatch.setattr(inbounds,"apply_agent",apply)
        monkeypatch.setattr(inbounds,"record",lambda *a,**k:None)
        yield SimpleNamespace(db=db,admin=admin,node=node,inbound=inbound,client=client,applies=applies)
    engine.dispose()


def test_new_inbound_without_peers_is_valid(scenario):
    s=scenario
    config=render_inbound(s.inbound,s.node,s.db)["config"]
    assert "ListenPort = 443" in config
    assert "[Peer]" not in config


def test_issue_then_sync_preserves_phone_peer(scenario):
    s=scenario
    result=credentials.issue(s.client.id,admin=s.admin,db=s.db)
    inbounds.sync_inbound(s.inbound.id,request=None,admin=s.admin,db=s.db)
    assert len(s.applies)==2
    for config in s.applies:
        assert config.count("[Peer]")==1
        assert "PublicKey = "+result["public_identifier"] in config
        assert "AllowedIPs = 10.10.0.2/32" in config


def test_download_again_at_device_limit_reuses_key(scenario):
    s=scenario
    first=credentials.issue(s.client.id,admin=s.admin,db=s.db)
    second=credentials.issue(s.client.id,admin=s.admin,db=s.db)
    assert first["credential_id"]==second["credential_id"]
    assert first["public_identifier"]==second["public_identifier"]
    assert s.db.query(Device).count()==1
    assert s.db.query(ClientCredential).count()==1
    assert s.applies[-1].count("[Peer]")==1


@pytest.mark.parametrize("state",[ResourceState.revoked,ResourceState.suspended,ResourceState.expired])
def test_sync_omits_inactive_clients(scenario,state):
    s=scenario
    credentials.issue(s.client.id,admin=s.admin,db=s.db)
    s.client.status=state;s.db.commit()
    assert "[Peer]" not in render_inbound(s.inbound,s.node,s.db)["config"]


def test_sync_omits_expired_client_even_before_worker(scenario):
    s=scenario
    credentials.issue(s.client.id,admin=s.admin,db=s.db)
    s.client.expires_at=datetime.now(timezone.utc)-timedelta(seconds=1);s.db.commit()
    assert "[Peer]" not in render_inbound(s.inbound,s.node,s.db)["config"]


def test_failed_apply_leaves_no_credential(scenario,monkeypatch):
    from fastapi import HTTPException
    s=scenario
    def fail(*args,**kwargs):raise RuntimeError("test node unreachable")
    monkeypatch.setattr(credentials,"apply_agent",fail)
    with pytest.raises(HTTPException) as error:credentials.issue(s.client.id,admin=s.admin,db=s.db)
    assert error.value.status_code==502
    assert s.db.query(Device).count()==0
    assert s.db.query(ClientCredential).count()==0


def test_installer_scopes_redirect_and_exchanges_after_dependencies(tmp_path):
    script=provisioning.INSTALL_SCRIPT
    path=tmp_path/"install.sh";path.write_text(script)
    subprocess.run(["bash","-n",str(path)],check=True)
    redirects=[line for line in script.splitlines() if "-I PREROUTING" in line and "REDIRECT" in line]
    assert redirects and all('-d "$PUBLIC_HOST"' in line for line in redirects)
    assert "ppa:amnezia/ppa" in script
    assert "apt-get install -y amneziawg" in script
    assert "AmneziaWG=$(command -v awg" in script
    assert script.index('"$BASE/venv/bin/pip" install --no-cache-dir')<script.index('EXCHANGE="$(curl')


def test_packaged_agents_are_identical():
    from pathlib import Path
    root=Path(__file__).resolve().parents[2]
    expected=(root/"node-agent/app.py").read_bytes()
    assert (root/"backend/app/node-agent/app.py").read_bytes()==expected
    assert (root/"backend/node-agent/app.py").read_bytes()==expected
