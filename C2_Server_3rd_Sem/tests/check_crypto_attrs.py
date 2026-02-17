
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone

# Generate a dummy cert
key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, u'Test')])
builder = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
)
cert = builder.sign(key, hashes.SHA256(), default_backend())

print('Certificate Attributes:')
print(f'Has not_valid_before_utc: {hasattr(cert, "not_valid_before_utc")}')
print(f'Has not_valid_after_utc: {hasattr(cert, "not_valid_after_utc")}')

print('CertificateBuilder Attributes:')
# Create a fresh builder instance
fresh_builder = x509.CertificateBuilder()
print(f'Has not_valid_before_utc: {hasattr(fresh_builder, "not_valid_before_utc")}')
