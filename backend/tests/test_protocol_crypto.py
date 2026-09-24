from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from app.services.credentials import wg_keypair,openvpn_ca,openvpn_server,openvpn_client,openvpn_tls_crypt_key
from app.services.openvpn_revoke import create_empty_crl,revoke_certificate

def test_wireguard_keypair():
 private,public=wg_keypair()
 assert len(private)==44 and len(public)==44

def test_openvpn_chain_and_crl():
 ca,ca_key=openvpn_ca()
 cert,key=openvpn_server(ca,ca_key,"server")
 client,client_key=openvpn_client(ca,ca_key,"client")
 assert x509.load_pem_x509_certificate(cert.encode()).issuer==x509.load_pem_x509_certificate(ca.encode()).subject
 crl=create_empty_crl(ca,ca_key)
 revoked=revoke_certificate(crl,client,ca_key,ca)
 parsed=x509.load_pem_x509_crl(revoked.encode())
 assert len(list(parsed))==1

def test_tls_crypt_key_format():
 key=openvpn_tls_crypt_key()
 assert key.startswith("-----BEGIN OpenVPN Static key V1-----")
 assert key.endswith("-----END OpenVPN Static key V1-----\n")
 assert len(key.splitlines())==18


def test_rendered_wireguard_runtime_expectations():
 from app.services.agent_client import _expected_wireguard
 from app.services.credentials import wg_public_key
 server_private,server_public=wg_keypair()
 _,peer_public=wg_keypair()
 config=f"""[Interface]
PrivateKey = {server_private}
Address = 10.10.0.1/24
ListenPort = 51820

[Peer]
PublicKey = {peer_public}
AllowedIPs = 10.10.0.2/32
"""
 live_public,peers=_expected_wireguard(config)
 assert live_public==server_public==wg_public_key(server_private)
 assert peers==[(peer_public,"10.10.0.2/32")]
