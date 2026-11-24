#!/bin/sh
# Prepare a fresh private bundle for the two loopback browser-preview vhosts.
# Never overwrite an existing trust anchor, edit Nginx or start a service.
set -eu
umask 077
[ "$#" -eq 1 ] || { echo "usage: $0 NEW_DIRECTORY" >&2; exit 2; }
mkdir -m 700 -- "$1"
cd -- "$1"
# Use an ephemeral CA signing key. Retain only the trust anchor and leaf key.
python3 - <<'PY'
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

now = datetime.now(timezone.utc)
hosts = ["ubid-preview.hodlxxi.test", "social-preview.hodlxxi.test"]
ca = ec.generate_private_key(ec.SECP256R1())
ca_key_id = x509.SubjectKeyIdentifier.from_public_key(ca.public_key())
issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "HODLXXI Preview CA " + ca_key_id.digest.hex()[:16])])
leaf = ec.generate_private_key(ec.SECP256R1())

def certificate(key, name, days, is_ca):
    return (x509.CertificateBuilder().issuer_name(issuer).subject_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=days))
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_key_id), critical=False)
            .add_extension(x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None), critical=True)
            .add_extension(x509.KeyUsage(not is_ca, False, False, False, False, is_ca, is_ca, False, False),
                           critical=True))

pem = serialization.Encoding.PEM
anchor = certificate(ca, issuer, 90, True).sign(ca, hashes.SHA256())
server = (certificate(leaf, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])]), 30, False)
          .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hosts]), critical=False)
          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
          .sign(ca, hashes.SHA256()))
Path("preview-ca.pem").write_bytes(anchor.public_bytes(pem))
Path("https.pem").write_bytes(server.public_bytes(pem))
Path("https.key").write_bytes(leaf.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
PY
for name in ubid-preview.hodlxxi.test social-preview.hodlxxi.test; do
    openssl verify -purpose sslserver -verify_hostname "$name" -CAfile preview-ca.pem https.pem
done
