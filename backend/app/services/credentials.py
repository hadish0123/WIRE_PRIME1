import base64,hashlib,ipaddress
from datetime import datetime,timezone,timedelta
from cryptography.hazmat.primitives.asymmetric import x25519,rsa
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption
from cryptography import x509
from cryptography.x509.oid import NameOID
from .security import encrypt_secret,decrypt_secret
def wg_keypair():
 private=x25519.X25519PrivateKey.generate();pub=private.public_key()
 return base64.b64encode(private.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())).decode(),base64.b64encode(pub.public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
def _name(common):return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,common)])
def openvpn_ca():
 key=rsa.generate_private_key(public_exponent=65537,key_size=3072);now=datetime.now(timezone.utc)
 cert=x509.CertificateBuilder().subject_name(_name("PRIMEVPN CA")).issuer_name(_name("PRIMEVPN CA")).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True,path_length=1),critical=True).sign(key,__import__("cryptography").hazmat.primitives.hashes.SHA256())
 return cert.public_bytes(Encoding.PEM).decode(),key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()).decode()
def openvpn_client(ca_pem,ca_key_pem,common_name):
 ca=x509.load_pem_x509_certificate(ca_pem.encode());ca_key=__import__("cryptography").hazmat.primitives.serialization.load_pem_private_key(ca_key_pem.encode(),password=None)
 key=rsa.generate_private_key(public_exponent=65537,key_size=2048);now=datetime.now(timezone.utc)
 cert=x509.CertificateBuilder().subject_name(_name(common_name)).issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=825)).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).sign(ca_key,__import__("cryptography").hazmat.primitives.hashes.SHA256())
 return cert.public_bytes(Encoding.PEM).decode(),key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()).decode()
def fingerprint(value):return hashlib.sha256(value.encode()).hexdigest()
