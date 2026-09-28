#!/usr/bin/env python3
"""Generate the shared RFC 3161 verifier fixtures without persisting private keys.

Requires OpenSSL 3 and the Python ``cryptography`` package. The output is intentionally committed: every verifier port consumes
the exact same real CMS tokens, certificate chains, pins, and CRLs.
"""

from __future__ import annotations

import base64
import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
REPO = PACKAGE_ROOT.parents[1]
OPENSSL = os.environ.get("OPENSSL", "openssl")
UTC = timezone.utc


def openssl(directory: Path, *args: str) -> None:
    """Run the OpenSSL CLI in ``directory``. The binary comes from the developer's own ``OPENSSL``
    env var (this is an offline, maintainer-run fixture generator, never shipped or served); argv is
    a list, so there is no shell and no argument is re-parsed."""
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
    subprocess.run([OPENSSL, *args], cwd=directory, check=True, capture_output=True)

ANCHOR = {
    # merkleRoot([hashLeaf(merkleRoot([hashLeaf("evt")]))]); used by the bundle integration test.
    "dailyRoot": "a204ff2cae2e6ec2baba2f21ac1dee4ad59d93ab00fc63e279abc139efcdae60",
    # Replaced in main() by the generation instant: the token's genTime is "now", and DEWP §5.3 bounds
    # how far a witness time may sit from the checkpoint time the anchor claims.
    "timestamp": "2026-09-25T12:00:00.000Z",
    "issuer": "https://tsa.example.test",
    "algorithm": "ES256",
    "keyId": "rfc3161-vector-tsa",
    "signature": "",
    "kind": "RFC3161",
    # The checkpoint's position (DEWP §5.2): the genesis checkpoint holding the single "evt" leaf.
    "seqStart": "1",
    "seqEnd": "1",
}


def chain_hash(prev: str, root: str, seq_start: str, seq_end: str, entry_count: int, anchored_at: str) -> str:
    """DEWP §5.4: SHA-256(0x04 || JCS([prev, root, seqStart, seqEnd, String(entryCount), anchoredAt]))."""
    preimage = json.dumps([prev, root, seq_start, seq_end, str(entry_count), anchored_at], separators=(",", ":"))
    return hashlib.sha256(b"\x04" + preimage.encode()).hexdigest()


def dt(text: str) -> datetime:
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


def key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def make_ca(common_name: str):
    private = key()
    subject = name(common_name)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt("2026-09-01T00:00:00"))
        .not_valid_after(dt("2036-09-01T00:00:00"))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private.public_key()), critical=False)
        .sign(private, hashes.SHA256())
    )
    return private, cert


def make_signer(ca_key, ca_cert, common_name: str, eku, serial: int):
    private = key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(private.public_key())
        .serial_number(serial)
        .not_valid_before(dt("2026-09-01T00:00:00"))
        .not_valid_after(dt("2036-09-01T00:00:00"))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(False, True, False, False, False, False, False, False, False), critical=True)
        # RFC 3161 requires timeStamping as the sole, critical EKU.
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return private, cert


def pem_cert(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def write_private(path: Path, private) -> None:
    path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    path.chmod(0o600)


def digest(anchor: dict) -> bytes:
    preimage = json.dumps(
        [anchor["dailyRoot"], anchor["timestamp"], anchor["issuer"], anchor["algorithm"],
         anchor["seqStart"], anchor["seqEnd"], anchor["chainHash"]],
        separators=(",", ":"),
    )
    return hashlib.sha256(b"\x03" + preimage.encode()).digest()


def der_read(data: bytes, offset: int) -> tuple[int, int, int]:
    tag, first = data[offset], data[offset + 1]
    if first < 0x80:
        start, length = offset + 2, first
    else:
        count = first & 0x7F
        start = offset + 2 + count
        length = int.from_bytes(data[offset + 2:start], "big")
    return tag, start, start + length


def der_wrap(tag: int, content: bytes) -> bytes:
    length = len(content)
    encoded = bytes([length]) if length < 128 else bytes([0x80 + (length.bit_length() + 7) // 8]) + length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag]) + encoded + content


def alter_digest_set(token_der: bytes, mode: str) -> bytes:
    """Mutate only SignedData.digestAlgorithms; signerInfo remains the genuine SHA-256 value."""
    _, outer_start, outer_end = der_read(token_der, 0)
    _, oid_start, oid_end = der_read(token_der, outer_start)
    oid_tlv = token_der[outer_start:oid_end]
    explicit_offset = oid_end
    _, explicit_start, explicit_end = der_read(token_der, explicit_offset)
    _, signed_start, signed_end = der_read(token_der, explicit_start)
    _, version_start, version_end = der_read(token_der, signed_start)
    version_tlv = token_der[signed_start:version_end]
    set_offset = version_end
    _, set_start, set_end = der_read(token_der, set_offset)
    set_content = token_der[set_start:set_end]
    if mode == "mismatch":
        # SHA-256 OID ...2.1 -> SHA-384 ...2.2, same DER width.
        needle = bytes.fromhex("608648016503040201")
        assert needle in set_content
        new_set = der_wrap(0x31, set_content.replace(needle, bytes.fromhex("608648016503040202"), 1))
    elif mode == "duplicate":
        new_set = der_wrap(0x31, set_content + set_content)
    else:
        raise ValueError(mode)
    signed_content = version_tlv + new_set + token_der[set_end:signed_end]
    explicit = der_wrap(0xA0, der_wrap(0x30, signed_content))
    return der_wrap(0x30, oid_tlv + explicit)


def token(work: Path, label: str, anchor: dict, signer_key, signer_cert, ca_cert, imprint: bytes | None = None, signer_digest: str = "sha256") -> tuple[bytes, bytes, bytes]:
    directory = work / label
    directory.mkdir(mode=0o700)
    (directory / "signer.pem").write_text(pem_cert(signer_cert))
    (directory / "chain.pem").write_text(pem_cert(ca_cert))
    write_private(directory / "signer-key.pem", signer_key)
    (directory / "serial").write_text("01\n")
    (directory / "tsa.cnf").write_text(
        "[tsa]\ndefault_tsa=tsa_config\n[tsa_config]\n"
        "serial=serial\ncrypto_device=builtin\nsigner_cert=signer.pem\n"
        f"certs=chain.pem\nsigner_key=signer-key.pem\nsigner_digest={signer_digest}\n"
        "default_policy=1.3.6.1.4.1.57264.1\ndigests=sha256\n"
        "accuracy=secs:1\nordering=no\ntsa_name=yes\ness_cert_id_chain=no\ness_cert_id_alg=sha256\n"
    )
    query = directory / "query.tsq"
    openssl(directory, "ts", "-query", "-digest", (imprint or digest(anchor)).hex(), "-sha256", "-cert", "-out", str(query))
    response = directory / "response.tsr"
    openssl(directory, "ts", "-reply", "-config", "tsa.cnf", "-queryfile", "query.tsq", "-out", "response.tsr")
    token_path = directory / "token.der"
    openssl(directory, "ts", "-reply", "-in", "response.tsr", "-token_out", "-out", "token.der")
    return token_path.read_bytes(), query.read_bytes(), response.read_bytes()


def crl(ca_key, ca_cert, revoked_serial: int | None, last: datetime, next_: datetime) -> str:
    builder = x509.CertificateRevocationListBuilder().issuer_name(ca_cert.subject).last_update(last).next_update(next_)
    if revoked_serial is not None:
        revoked = x509.RevokedCertificateBuilder().serial_number(revoked_serial).revocation_date(last).build()
        builder = builder.add_revoked_certificate(revoked)
    return builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode("ascii")


def wrong_eku_cms(work: Path, valid: bytes, signer_key, signer_cert, ca_cert) -> bytes:
    """Make structurally valid CMS around genuine TSTInfo using a non-TSA signer certificate."""
    directory = work / "bad-eku"
    directory.mkdir(mode=0o700)
    (directory / "valid.der").write_bytes(valid)
    (directory / "signer.pem").write_text(pem_cert(signer_cert))
    (directory / "chain.pem").write_text(pem_cert(ca_cert))
    write_private(directory / "signer-key.pem", signer_key)
    openssl(directory, "cms", "-verify", "-binary", "-inform", "DER", "-in", "valid.der", "-noverify", "-out", "info.der")
    openssl(directory, "cms", "-sign", "-binary", "-nodetach", "-in", "info.der", "-signer", "signer.pem", "-inkey", "signer-key.pem", "-certfile", "chain.pem", "-outform", "DER", "-out", "bad.der")
    return (directory / "bad.der").read_bytes()


def token_gen_time(work: Path, token_der: bytes) -> datetime:
    """Read signed genTime only to derive coherent evaluation and CRL windows."""
    directory = work / "read-gentime"
    directory.mkdir(mode=0o700)
    (directory / "token.der").write_bytes(token_der)
    openssl(directory, "cms", "-verify", "-binary", "-inform", "DER", "-in", "token.der", "-noverify", "-out", "info.der")
    match = re.search(rb"(20\d{12})(?:\.\d+)?Z", (directory / "info.der").read_bytes())
    if not match:
        raise RuntimeError("generated TSTInfo has no supported GeneralizedTime")
    return datetime.strptime(match.group(1).decode(), "%Y%m%d%H%M%S").replace(tzinfo=UTC)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, help="write one vector file at this path")
    args = parser.parse_args()
    ca_key, ca = make_ca("Intyga RFC3161 Vector Root")
    wrong_ca_key, wrong_ca = make_ca("Untrusted RFC3161 Vector Root")
    tsa_key, tsa = make_signer(ca_key, ca, "Intyga Vector TSA", ExtendedKeyUsageOID.TIME_STAMPING, 0x3161)
    bad_key, bad_cert = make_signer(ca_key, ca, "Wrong EKU TSA", ExtendedKeyUsageOID.SERVER_AUTH, 0x3162)
    anchor = dict(ANCHOR)
    now = datetime.now(UTC)
    anchor["timestamp"] = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    anchor["chainHash"] = chain_hash("", anchor["dailyRoot"], anchor["seqStart"], anchor["seqEnd"], 1, anchor["timestamp"])
    divergence_anchor = {**anchor, "dailyRoot": "a" * 64}
    with tempfile.TemporaryDirectory(prefix="intyga-rfc3161-") as raw:
        work = Path(raw)
        valid, _, _ = token(work, "valid", anchor, tsa_key, tsa, ca)
        divergence_token, _, _ = token(work, "divergence", divergence_anchor, tsa_key, tsa, ca)
        sha1_token, _, _ = token(work, "weak-sha1", anchor, tsa_key, tsa, ca, signer_digest="sha1")
        md5_token, _, _ = token(work, "weak-md5", anchor, tsa_key, tsa, ca, signer_digest="md5")
        sha384_token, _, _ = token(work, "sha384", anchor, tsa_key, tsa, ca, signer_digest="sha384")
        sha512_token, _, _ = token(work, "sha512", anchor, tsa_key, tsa, ca, signer_digest="sha512")
        producer_token, producer_query, producer_response = token(
            work, "producer", anchor, tsa_key, tsa, ca, hashlib.sha256(b"daily-root").digest()
        )
        bad_eku = wrong_eku_cms(work, valid, bad_key, bad_cert, ca)
        gen_time = token_gen_time(work, valid)

    certificate_start = dt("2026-09-01T00:00:00")
    certificate_end = dt("2036-09-01T00:00:00")
    if not certificate_start <= gen_time < certificate_end - timedelta(days=1):
        raise RuntimeError("generate RFC3161 fixtures only within certificate window 2026-09-01..2036-08-31")
    valid_at = int((gen_time + timedelta(days=1)).timestamp())

    evidence = base64.b64encode(valid).decode()
    anchor["evidence"] = evidence
    divergence_anchor["evidence"] = base64.b64encode(divergence_token).decode()
    signer_der = tsa.public_bytes(serialization.Encoding.DER)
    trust = {
        "caPem": pem_cert(ca),
        "signerCertificateSha256": hashlib.sha256(signer_der).hexdigest(),
        "revocation": "unchecked",
        "verificationTime": valid_at,
    }
    valid_crl = crl(ca_key, ca, None, gen_time, gen_time + timedelta(days=31))
    revoked_crl = crl(ca_key, ca, tsa.serial_number, gen_time, gen_time + timedelta(days=31))
    stale_crl = crl(ca_key, ca, None, gen_time - timedelta(days=2), gen_time - timedelta(seconds=1))

    def case(name_, anchor_=None, trust_=None, expected=True):
        return {"name": name_, "anchor": anchor_ if anchor_ is not None else anchor, "trust": trust_, "expected": expected}

    tampered = bytearray(valid)
    tampered[-1] ^= 1
    wrong_digest_anchor = {**anchor, "dailyRoot": "f" * 64}
    wrong_issuer_anchor = {**anchor, "issuer": "https://other-tsa.example.test"}
    malformed_anchor = {**anchor, "evidence": base64.b64encode(b"not DER").decode()}
    trailing_anchor = {**anchor, "evidence": base64.b64encode(valid + b"trailing").decode()}
    tampered_anchor = {**anchor, "evidence": base64.b64encode(tampered).decode()}
    bad_eku_anchor = {**anchor, "evidence": base64.b64encode(bad_eku).decode()}
    weak_sha1_anchor = {**anchor, "evidence": base64.b64encode(sha1_token).decode()}
    weak_md5_anchor = {**anchor, "evidence": base64.b64encode(md5_token).decode()}
    sha384_anchor = {**anchor, "evidence": base64.b64encode(sha384_token).decode()}
    sha512_anchor = {**anchor, "evidence": base64.b64encode(sha512_token).decode()}
    mismatch_anchor = {**anchor, "evidence": base64.b64encode(alter_digest_set(valid, "mismatch")).decode()}
    duplicate_anchor = {**anchor, "evidence": base64.b64encode(alter_digest_set(valid, "duplicate")).decode()}
    data = {
        "version": 1,
        "note": "Shared real OpenSSL RFC 3161/CMS fixtures. Private keys are generated only in a temporary directory and are not persisted.",
        "producer": {
            "digestHex": hashlib.sha256(b"daily-root").hexdigest(),
            "query": base64.b64encode(producer_query).decode(),
            "response": base64.b64encode(producer_response).decode(),
            "token": base64.b64encode(producer_token).decode(),
            "trust": trust,
        },
        "cases": [
            case("valid-unchecked", trust_=trust),
            case("valid-different-root-for-divergence", divergence_anchor, trust),
            case("tampered-token", tampered_anchor, trust, False),
            case("wrong-anchor-digest", wrong_digest_anchor, trust, False),
            case("wrong-anchor-issuer", wrong_issuer_anchor, trust, False),
            case("wrong-ca", trust_={**trust, "caPem": pem_cert(wrong_ca)}, expected=False),
            case("wrong-signer-pin", trust_={**trust, "signerCertificateSha256": "00" * 32}, expected=False),
            case("certificate-expired-at-evaluation", trust_={**trust, "verificationTime": int((certificate_end + timedelta(days=1)).timestamp())}, expected=False),
            case("certificate-not-yet-valid-at-evaluation", trust_={**trust, "verificationTime": int(certificate_start.timestamp()) - 1}, expected=False),
            case("bad-timestamping-eku", bad_eku_anchor, {**trust, "signerCertificateSha256": hashlib.sha256(bad_cert.public_bytes(serialization.Encoding.DER)).hexdigest()}, False),
            case("weak-cms-sha1", weak_sha1_anchor, trust, False),
            case("weak-cms-md5", weak_md5_anchor, trust, False),
            case("valid-cms-sha384", sha384_anchor, trust),
            case("valid-cms-sha512", sha512_anchor, trust),
            case("cms-digest-set-signerinfo-mismatch", mismatch_anchor, trust, False),
            case("cms-duplicate-digest-set-algorithm", duplicate_anchor, trust, False),
            case("missing-trust", trust_=None, expected=False),
            case("malformed-token", malformed_anchor, trust, False),
            case("trailing-der", trailing_anchor, trust, False),
            case("future-generation-time", trust_={**trust, "verificationTime": int(gen_time.timestamp()) - 1}, expected=False),
            case("valid-current-crl", trust_={**trust, "revocation": "crl", "crlPem": valid_crl}),
            case("revoked-signer", trust_={**trust, "revocation": "crl", "crlPem": revoked_crl}, expected=False),
            case("stale-crl", trust_={**trust, "revocation": "crl", "crlPem": stale_crl}, expected=False),
            case("missing-crl", trust_={**trust, "revocation": "crl"}, expected=False),
        ],
    }
    encoded = json.dumps(data, indent=2) + "\n"
    monorepo_vector = REPO / "packages/mcp-schemas/vectors/rfc3161-vectors.json"
    targets = [args.output] if args.output else (
        [monorepo_vector, REPO / "apps/marketing/public/specs/v1.0/vectors/rfc3161-vectors.json"]
        if monorepo_vector.parent.exists()
        else [PACKAGE_ROOT / "vectors/rfc3161-vectors.json"]
    )
    for target in targets:
        assert target is not None
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(encoded)
    print(f"wrote {len(data['cases'])} cases to " + " and ".join(str(target) for target in targets))


if __name__ == "__main__":
    main()
