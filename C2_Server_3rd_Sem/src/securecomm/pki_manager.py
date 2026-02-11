"""
SecureComm PKI Manager
Handles Certificate Authority, certificate generation, validation, and revocation

Author: Shadow Junior
"""

import os
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Tuple, List, Dict

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend


class PKIManager:
    """
    Manages PKI infrastructure including:
    - Root CA generation
    - Certificate signing requests (CSR)
    - Certificate issuance
    - Certificate validation
    - Certificate revocation (CRL)
    """
    
    def __init__(self, pki_path: str = "data/pki"):
        """
        Initialize PKI Manager
        
        Args:
            pki_path: Base path for PKI data storage
        """
        self.pki_path = Path(pki_path)
        self.ca_path = self.pki_path / "ca"
        self.operators_path = self.pki_path / "operators"
        self.agents_path = self.pki_path / "agents"
        self.crl_path = self.pki_path / "crl"
        
        # Create directories if they don't exist
        for path in [self.ca_path, self.operators_path, self.agents_path, self.crl_path]:
            path.mkdir(parents=True, exist_ok=True)
        
        # Certificate database (tracks issued certificates)
        self.cert_db_path = self.pki_path / "certificates.json"
        self.cert_db = self._load_cert_db()
        
        # Revoked certificates database
        self.revoked_db_path = self.pki_path / "revoked.json"
        self.revoked_db = self._load_revoked_db()
    
    def _load_cert_db(self) -> Dict:
        """Load certificate database from disk"""
        if self.cert_db_path.exists():
            with open(self.cert_db_path, 'r') as f:
                return json.load(f)
        return {"certificates": []}
    
    def _save_cert_db(self):
        """Save certificate database to disk"""
        with open(self.cert_db_path, 'w') as f:
            json.dump(self.cert_db, f, indent=2)
    
    def _load_revoked_db(self) -> Dict:
        """Load revoked certificates database"""
        if self.revoked_db_path.exists():
            with open(self.revoked_db_path, 'r') as f:
                return json.load(f)
        return {"revoked": []}
    
    def _save_revoked_db(self):
        """Save revoked certificates database"""
        with open(self.revoked_db_path, 'w') as f:
            json.dump(self.revoked_db, f, indent=2)

    def _crl_file_path(self) -> Path:
        return self.crl_path / "ca_root.crl"

    def _parse_revocation_time(self, value: Optional[str]) -> datetime:
        if not value:
            return datetime.now(timezone.utc)
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return datetime.now(timezone.utc)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _reason_flag(self, reason: str) -> x509.ReasonFlags:
        reason_map = {
            "key_compromise": x509.ReasonFlags.key_compromise,
            "ca_compromise": x509.ReasonFlags.ca_compromise,
            "affiliation_changed": x509.ReasonFlags.affiliation_changed,
            "superseded": x509.ReasonFlags.superseded,
            "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
            "certificate_hold": x509.ReasonFlags.certificate_hold,
            "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
            "aa_compromise": x509.ReasonFlags.aa_compromise,
            "unspecified": x509.ReasonFlags.unspecified,
        }
        return reason_map.get(reason, x509.ReasonFlags.unspecified)

    def generate_crl(
        self,
        ca_cert: x509.Certificate,
        ca_private_key: ed25519.Ed25519PrivateKey,
        validity_days: int = 30,
    ) -> x509.CertificateRevocationList:
        """Generate and persist a signed CRL."""
        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(now)
            .next_update(now + timedelta(days=validity_days))
        )

        revoked_entries: Dict[str, Dict[str, str]] = {
            entry["serial_number"]: entry
            for entry in self.revoked_db.get("revoked", [])
            if entry.get("serial_number")
        }
        for cert in self.cert_db.get("certificates", []):
            if cert.get("revoked"):
                serial = str(cert.get("serial_number"))
                revoked_entries.setdefault(
                    serial,
                    {
                        "serial_number": serial,
                        "revoked_at": cert.get("revoked_at"),
                        "reason": cert.get("revoke_reason", "unspecified"),
                    },
                )

        for entry in revoked_entries.values():
            try:
                serial_number = int(entry["serial_number"])
            except (TypeError, ValueError):
                continue
            revoked_at = self._parse_revocation_time(entry.get("revoked_at"))
            revoked_builder = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial_number)
                .revocation_date(revoked_at)
                .add_extension(x509.CRLReason(self._reason_flag(entry.get("reason", "unspecified"))), critical=False)
            )
            builder = builder.add_revoked_certificate(revoked_builder.build(default_backend()))

        crl = builder.sign(private_key=ca_private_key, algorithm=None)
        crl_path = self._crl_file_path()
        with open(crl_path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))
        return crl

    def load_crl(self) -> Optional[x509.CertificateRevocationList]:
        """Load CRL from disk if available."""
        crl_path = self._crl_file_path()
        if not crl_path.exists():
            return None
        with open(crl_path, "rb") as f:
            return x509.load_pem_x509_crl(f.read(), default_backend())

    def _validate_crl(self, crl: x509.CertificateRevocationList, ca_cert: x509.Certificate) -> None:
        if crl.issuer != ca_cert.subject:
            raise ValueError("CRL issuer does not match CA")
        ca_public_key = ca_cert.public_key()
        try:
            ca_public_key.verify(crl.signature, crl.tbs_certlist_bytes)
        except Exception as exc:
            raise ValueError(f"CRL signature validation failed: {exc}")
        now = datetime.now(timezone.utc)
        last_update = crl.last_update
        if last_update.tzinfo is None:
            last_update = last_update.replace(tzinfo=timezone.utc)
        next_update = crl.next_update
        if next_update:
            if next_update.tzinfo is None:
                next_update = next_update.replace(tzinfo=timezone.utc)
            if now > next_update:
                raise ValueError("CRL has expired")
        if now < last_update:
            raise ValueError("CRL not yet valid")

    def _is_revoked_in_db(self, serial_number: str) -> bool:
        for cert in self.cert_db.get("certificates", []):
            if cert["serial_number"] == serial_number:
                return cert.get("revoked", False)
        for entry in self.revoked_db.get("revoked", []):
            if entry.get("serial_number") == serial_number:
                return True
        return False

    def _is_revoked_in_crl(self, crl: x509.CertificateRevocationList, serial_number: int) -> bool:
        for revoked in crl:
            if revoked.serial_number == serial_number:
                return True
        return False
    
    def generate_key_pair(self) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """
        Generate Ed25519 key pair for signatures
        
        Returns:
            Tuple of (private_key, public_key)
        
        Security:
            - Uses Ed25519 for fast, secure signatures
            - 128-bit security level
            - Deterministic signatures
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    
    def generate_root_ca(
        self, 
        common_name: str = "SecureComm Root CA",
        validity_days: int = 3650,
        password: Optional[bytes] = None
    ) -> Tuple[x509.Certificate, ed25519.Ed25519PrivateKey]:
        """
        Generate self-signed root CA certificate
        
        Args:
            common_name: CA common name
            validity_days: Certificate validity in days (default 10 years)
            password: Optional password to encrypt private key
        
        Returns:
            Tuple of (certificate, private_key)
        
        Security:
            - Ed25519 signatures (fast, secure)
            - Self-signed root of trust
            - Private key can be password-protected
        """
        # Generate key pair
        private_key, public_key = self.generate_key_pair()
        
        # Build certificate subject
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bagmati"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Patan"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureComm"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # Build certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
                critical=False
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .sign(private_key, algorithm=None)  # Ed25519 doesn't need hash algorithm
        )
        
        # Save certificate
        cert_path = self.ca_path / "ca_root.crt"
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Save private key (encrypted if password provided)
        key_path = self.ca_path / "ca_root.key"
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            ))
        
        # Set restrictive permissions on private key
        os.chmod(key_path, 0o600)

        self.generate_crl(cert, private_key)
        
        print(f"✅ Root CA generated: {cert_path}")
        print(f"🔐 Private key saved: {key_path}")
        
        return cert, private_key
    
    def create_csr(
        self,
        private_key: ed25519.Ed25519PrivateKey,
        common_name: str,
        organization: str = "SecureComm",
        **kwargs
    ) -> x509.CertificateSigningRequest:
        """
        Create Certificate Signing Request
        
        Args:
            private_key: Private key for CSR
            common_name: Certificate common name
            organization: Organization name
            **kwargs: Additional name attributes
        
        Returns:
            Certificate Signing Request
        """
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, kwargs.get('country', 'NP')),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, kwargs.get('state', 'Bagmati')),
            x509.NameAttribute(NameOID.LOCALITY_NAME, kwargs.get('locality', 'Patan')),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(subject)
            .sign(private_key, algorithm=None)
        )
        
        return csr
    
    def sign_csr(
        self,
        csr: x509.CertificateSigningRequest,
        ca_cert: x509.Certificate,
        ca_private_key: ed25519.Ed25519PrivateKey,
        validity_days: int = 365,
        cert_type: str = "operator"
    ) -> x509.Certificate:
        """
        Sign Certificate Signing Request with CA
        
        Args:
            csr: Certificate Signing Request to sign
            ca_cert: CA certificate
            ca_private_key: CA private key
            validity_days: Certificate validity in days
            cert_type: Type of certificate (operator, agent)
        
        Returns:
            Signed X.509 certificate
        
        Security:
            - Certificates are valid for 1 year by default
            - Includes proper key usage extensions
            - Serial number is cryptographically random
        """
        # Build signed certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                critical=False
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
                ]),
                critical=False
            )
            .sign(ca_private_key, algorithm=None)
        )
        
        # Save certificate to database
        serial_number = cert.serial_number
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        
        self.cert_db["certificates"].append({
            "serial_number": str(serial_number),
            "common_name": common_name,
            "type": cert_type,
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": cert.not_valid_after_utc.isoformat(),
            "revoked": False
        })
        self._save_cert_db()
        
        # Save certificate to appropriate directory
        save_path = self.operators_path if cert_type == "operator" else self.agents_path
        cert_file = save_path / f"{common_name.replace(' ', '_')}.crt"
        
        with open(cert_file, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"✅ Certificate signed and saved: {cert_file}")
        
        return cert
    
    def validate_certificate(
        self,
        cert: x509.Certificate,
        ca_cert: x509.Certificate
    ) -> bool:
        """
        Validate certificate against CA
        
        Args:
            cert: Certificate to validate
            ca_cert: CA certificate
        
        Returns:
            True if valid, raises exception otherwise
        
        Security:
            - Validates signature
            - Checks expiration
            - Verifies issuer
            - Checks revocation status
        """
        # Check if certificate is expired
        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            raise ValueError(f"Certificate expired or not yet valid")
        
        # Verify signature
        try:
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
            )
        except Exception as e:
            raise ValueError(f"Certificate signature validation failed: {e}")
        
        # Check if certificate is revoked (DB + CRL)
        serial_number = str(cert.serial_number)
        if self._is_revoked_in_db(serial_number):
            raise ValueError("Certificate has been revoked")
        crl = self.load_crl()
        if crl is not None:
            self._validate_crl(crl, ca_cert)
            if self._is_revoked_in_crl(crl, cert.serial_number):
                raise ValueError("Certificate has been revoked")
        
        # Check issuer matches CA
        if cert.issuer != ca_cert.subject:
            raise ValueError(f"Certificate issuer does not match CA")
        
        return True
    
    def revoke_certificate(self, serial_number: str, reason: str = "unspecified"):
        """
        Revoke a certificate
        
        Args:
            serial_number: Serial number of certificate to revoke
            reason: Reason for revocation
        """
        revoked_at = datetime.now(timezone.utc).isoformat()

        # Find certificate in database
        for cert in self.cert_db["certificates"]:
            if cert["serial_number"] == serial_number:
                cert["revoked"] = True
                cert["revoked_at"] = revoked_at
                cert["revoke_reason"] = reason
                break
        self._save_cert_db()

        # Add to revoked database
        self.revoked_db["revoked"].append({
            "serial_number": serial_number,
            "revoked_at": revoked_at,
            "reason": reason
        })
        self._save_revoked_db()

        try:
            ca_cert = self.load_ca_certificate()
            ca_private_key = self.load_ca_private_key()
            self.generate_crl(ca_cert, ca_private_key)
        except Exception:
            pass
        
        print(f"✅ Certificate {serial_number} revoked: {reason}")
    
    def is_revoked(self, serial_number: str) -> bool:
        """Check if certificate is revoked"""
        if self._is_revoked_in_db(serial_number):
            return True
        crl = self.load_crl()
        if crl is None:
            return False
        try:
            ca_cert = self.load_ca_certificate()
            self._validate_crl(crl, ca_cert)
        except Exception:
            return False
        try:
            return self._is_revoked_in_crl(crl, int(serial_number))
        except (TypeError, ValueError):
            return False
    
    def load_ca_certificate(self) -> x509.Certificate:
        """Load CA certificate from disk"""
        cert_path = self.ca_path / "ca_root.crt"
        if not cert_path.exists():
            raise FileNotFoundError(f"CA certificate not found: {cert_path}")
        
        with open(cert_path, 'rb') as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())
    
    def load_ca_private_key(self, password: Optional[bytes] = None) -> ed25519.Ed25519PrivateKey:
        """Load CA private key from disk"""
        key_path = self.ca_path / "ca_root.key"
        if not key_path.exists():
            raise FileNotFoundError(f"CA private key not found: {key_path}")
        
        with open(key_path, 'rb') as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=password,
                backend=default_backend()
            )
    
    def issue_certificate(
        self,
        common_name: str,
        cert_type: str = "operator",
        validity_days: int = 365,
        ca_password: Optional[bytes] = None
    ) -> Tuple[x509.Certificate, ed25519.Ed25519PrivateKey]:
        """
        Complete workflow: Generate key pair, create CSR, sign certificate
        
        Args:
            common_name: Certificate common name
            cert_type: Type of certificate (operator/agent)
            validity_days: Certificate validity
            ca_password: CA private key password
        
        Returns:
            Tuple of (certificate, private_key)
        """
        # Load CA
        ca_cert = self.load_ca_certificate()
        ca_private_key = self.load_ca_private_key(ca_password)
        
        # Generate new key pair
        private_key, public_key = self.generate_key_pair()
        
        # Create CSR
        csr = self.create_csr(private_key, common_name)
        
        # Sign CSR
        cert = self.sign_csr(csr, ca_cert, ca_private_key, validity_days, cert_type)
        
        # Save private key
        save_path = self.operators_path if cert_type == "operator" else self.agents_path
        key_file = save_path / f"{common_name.replace(' ', '_')}.key"
        
        with open(key_file, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        os.chmod(key_file, 0o600)
        
        print(f"✅ Complete certificate issued for: {common_name}")
        print(f"   Certificate: {save_path}/{common_name.replace(' ', '_')}.crt")
        print(f"   Private Key: {key_file}")
        
        return cert, private_key
    
    def list_certificates(self, cert_type: Optional[str] = None) -> List[Dict]:
        """
        List all issued certificates
        
        Args:
            cert_type: Filter by type (operator/agent) or None for all
        
        Returns:
            List of certificate dictionaries
        """
        certs = self.cert_db["certificates"]
        if cert_type:
            certs = [c for c in certs if c["type"] == cert_type]
        return certs
    
    def get_certificate_info(self, serial_number: str) -> Optional[Dict]:
        """Get certificate information by serial number"""
        for cert in self.cert_db["certificates"]:
            if cert["serial_number"] == serial_number:
                return cert
        return None
