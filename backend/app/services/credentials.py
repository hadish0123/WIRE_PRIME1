import base64,hashlib,secrets
from datetime import datetime,timezone,timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import x25519,rsa
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption
from cryptography.x509.oid import NameOID
def wg_keypair():
 private=x25519.X25519PrivateKey.generate();pub=private.public_key()
 return base64.b64encode(private.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())).decode(),base64.b64encode(pub.public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()

def wg_public_key(private_key:str)->str:
    """Derive the WireGuard public key from the actual stored private key."""
    raw=base64.b64decode(private_key.strip(),validate=True)
    if len(raw)!=32: raise ValueError("Invalid WireGuard private key length")
    private=x25519.X25519PrivateKey.from_private_bytes(raw)
    return base64.b64encode(private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
def _name(common):return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,common)])
def openvpn_ca():
 key=rsa.generate_private_key(public_exponent=65537,key_size=3072);now=datetime.now(timezone.utc)
 cert=x509.CertificateBuilder().subject_name(_name("PRIMEVPN CA")).issuer_name(_name("PRIMEVPN CA")).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True,path_length=1),critical=True).sign(key,hashes.SHA256())
 return cert.public_bytes(Encoding.PEM).decode(),key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()).decode()
def openvpn_server(ca_pem,ca_key_pem,common_name):
 return _signed_cert(ca_pem,ca_key_pem,common_name,True)
def openvpn_client(ca_pem,ca_key_pem,common_name):
 return _signed_cert(ca_pem,ca_key_pem,common_name,False)
def _signed_cert(ca_pem,ca_key_pem,common_name,server):
 ca=x509.load_pem_x509_certificate(ca_pem.encode());ca_key=serialization.load_pem_private_key(ca_key_pem.encode(),password=None);key=rsa.generate_private_key(public_exponent=65537,key_size=2048);now=datetime.now(timezone.utc)
 builder=x509.CertificateBuilder().subject_name(_name(common_name)).issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=825))
 builder=builder.add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
 builder=builder.add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH if server else x509.ExtendedKeyUsageOID.CLIENT_AUTH]),critical=False)
 cert=builder.sign(ca_key,hashes.SHA256())
 return cert.public_bytes(Encoding.PEM).decode(),key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()).decode()
def fingerprint(value):return hashlib.sha256(value.encode()).hexdigest()

def openvpn_tls_crypt_key():
    raw=secrets.token_bytes(256)
    lines=["-----BEGIN OpenVPN Static key V1-----"]
    for i in range(0,len(raw),16): lines.append(raw[i:i+16].hex())
    lines.append("-----END OpenVPN Static key V1-----")
    return "\n".join(lines)+"\n"
