import json
from datetime import datetime,timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from ..security import decrypt_secret,encrypt_secret
def revoke_certificate(existing_crl_pem,client_cert_pem,ca_key_pem,ca_cert_pem):
 ca=x509.load_pem_x509_certificate(ca_cert_pem.encode());ca_key=serialization.load_pem_private_key(ca_key_pem.encode(),password=None);cert=x509.load_pem_x509_certificate(client_cert_pem.encode())
 builder=x509.CertificateRevocationListBuilder().issuer_name(ca.subject).last_update(datetime.now(timezone.utc)).next_update(datetime.now(timezone.utc)+__import__("datetime").timedelta(days=30))
 if existing_crl_pem:
  old=x509.load_pem_x509_crl(existing_crl_pem.encode())
  for revoked in old:builder=builder.add_revoked_certificate(revoked)
 revoked=x509.RevokedCertificateBuilder().serial_number(cert.serial_number).revocation_date(datetime.now(timezone.utc)).build()
 builder=builder.add_revoked_certificate(revoked)
 return builder.sign(private_key=ca_key,algorithm=hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
