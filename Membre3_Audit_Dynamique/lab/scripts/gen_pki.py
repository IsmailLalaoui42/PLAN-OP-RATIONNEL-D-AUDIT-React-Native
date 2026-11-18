"""Génère la PKI du banc d'essai DAST (Membre 3).

- lab-root-ca      : AC racine « Lab Audit Root CA », installée comme AC système sur l'émulateur
                     (simule un certificat serveur signé par une AC publique).
- localhost-valid  : certificat serveur valide pour localhost (port 8443).
- wronghost        : certificat signé par la même AC mais pour « wrong.host.invalid » (port 8444, DAST-NET-06).
- localhost-expired: certificat pour localhost expiré depuis 30 jours (port 8445, DAST-NET-07).
- selfsigned       : certificat auto-signé pour localhost, hors chaîne de confiance (port 8446, DAST-NET-04b).

Usage : python gen_pki.py <dossier_sortie>
"""
import datetime as dt
import ipaddress
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

out = Path(sys.argv[1] if len(sys.argv) > 1 else "pki")
out.mkdir(parents=True, exist_ok=True)
now = dt.datetime.now(dt.timezone.utc)


def name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "MA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IACS Audit Lab (factice)"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def save(stem: str, key, cert) -> None:
    (out / f"{stem}.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (out / f"{stem}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


# AC racine
ca_key = ec.generate_private_key(ec.SECP256R1())
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(name("Lab Audit Root CA"))
    .issuer_name(name("Lab Audit Root CA"))
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - dt.timedelta(days=1))
    .not_valid_after(now + dt.timedelta(days=825))
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
    .sign(ca_key, hashes.SHA256())
)
save("lab-root-ca", ca_key, ca_cert)


def leaf(stem: str, cn: str, sans: list, not_before, not_after, issuer_key=ca_key, issuer_cert=ca_cert):
    key = ec.generate_private_key(ec.SECP256R1())
    san_entries = []
    for s in sans:
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(s)))
        except ValueError:
            san_entries.append(x509.DNSName(s))
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(issuer_cert.subject if issuer_cert is not None else name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    )
    cert = builder.sign(issuer_key if issuer_key is not None else key, hashes.SHA256())
    save(stem, key, cert)


leaf("localhost-valid", "localhost", ["localhost", "127.0.0.1"], now - dt.timedelta(days=1), now + dt.timedelta(days=397))
leaf("wronghost", "wrong.host.invalid", ["wrong.host.invalid"], now - dt.timedelta(days=1), now + dt.timedelta(days=397))
leaf("localhost-expired", "localhost", ["localhost", "127.0.0.1"], now - dt.timedelta(days=400), now - dt.timedelta(days=30))
leaf("selfsigned", "localhost", ["localhost", "127.0.0.1"], now - dt.timedelta(days=1), now + dt.timedelta(days=397),
     issuer_key=None, issuer_cert=None)

for p in sorted(out.iterdir()):
    print(p.name)
