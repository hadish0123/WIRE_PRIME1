import pytest
from app.services.protocols import WireGuardConfig,WireGuardPeer,render_wireguard,render_openvpn,render_amneziawg_options
KEY="A"*43
def test_wireguard_render():
 s=render_wireguard(WireGuardConfig(KEY,51820,"10.0.0.1/24",(WireGuardPeer(KEY,"10.0.0.2/32"),)))
 assert "[Interface]" in s and "AllowedIPs = 10.0.0.2/32" in s
def test_openvpn_rejects_bad_transport():
 with pytest.raises(ValueError):render_openvpn("10.8.0.0/24",1194,"icmp")
def test_amneziawg_parameters():
 s=render_amneziawg_options({"Jc":5,"Jmin":40,"Jmax":70,"S1":0,"S2":0,"S3":0,"S4":0,"H1":1,"H2":2,"H3":3,"H4":4})
 assert "Jc = 5" in s and "H4 = 4" in s


def test_inbound_network_validation_rejects_mismatched_prefix():
 from types import SimpleNamespace
 from fastapi import HTTPException
 from app.models import Protocol
 from app.routers.inbounds import _validate_network
 good=SimpleNamespace(network="10.10.0.0/24",address="10.10.0.1/24",protocol=Protocol.wireguard,interface="wg0")
 _validate_network(good)
 bad=SimpleNamespace(network="10.10.0.0/24",address="10.10.0.1/32",protocol=Protocol.wireguard,interface="wg0")
 with pytest.raises(HTTPException):
  _validate_network(bad)
