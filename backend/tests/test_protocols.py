import pytest
from app.services.protocols import WireGuardConfig,WireGuardPeer,render_wireguard,render_openvpn
KEY="A"*43
def test_wireguard_render():
 s=render_wireguard(WireGuardConfig(KEY,51820,"10.0.0.1/24",(WireGuardPeer(KEY,"10.0.0.2/32"),)))
 assert "[Interface]" in s and "AllowedIPs = 10.0.0.2/32" in s
def test_openvpn_rejects_bad_transport():
 with pytest.raises(ValueError):render_openvpn("10.8.0.0/24",1194,"icmp")
