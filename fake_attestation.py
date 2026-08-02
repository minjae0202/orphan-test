"""가짜 Sigstore/Fulcio attestation을 만드는 테스트 전용 스크립트.

Collector의 Sigstore 파서(bundle_parser/oidc_parser/rekor_parser)는 서명을
암호학적으로 검증하지 않고 필드만 파싱하기 때문에, 자체서명 인증서 +
손으로 조립한 DSSE bundle만으로도 npm attestation API 응답을 흉내낼 수
있다. 이 스크립트는 그 가짜 attestation을 만드는 용도로만 쓴다.

Collector 소스코드는 전혀 수정하지 않고, orphan-test 디렉토리 안에서만
사용한다.
"""
from __future__ import annotations

import base64
import datetime
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

FULCIO_OIDC_ISSUER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
FULCIO_GITHUB_WORKFLOW_REPOSITORY_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.5")
FULCIO_BUILD_SIGNER_URI_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.9")
DEFAULT_ISSUER = "https://token.actions.githubusercontent.com"


def _der_string(value: str) -> bytes:
    """Fulcio 커스텀 OID 확장이 쓰는 단순 ASN.1 문자열 래퍼(UTF8String)."""
    payload = value.encode("utf-8")
    if len(payload) >= 128:
        raise ValueError("DER short-form length만 지원 (테스트 데이터는 짧게 유지)")
    return bytes([0x0C, len(payload)]) + payload


def make_fake_fulcio_cert(
    *,
    owner_repo: str,
    workflow_path: str,
    ref: str = "refs/heads/main",
    issuer: str = DEFAULT_ISSUER,
) -> x509.Certificate:
    """Fulcio가 발급한 것처럼 보이는 자체서명 인증서를 만든다.

    실제 Fulcio 루트 CA에 체인되지 않는 순수 자체서명 인증서다. Collector가
    서명/체인을 검증하지 않는다는 사실을 이용해 필드만 진짜처럼 채운다.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject_uri = f"repo:{owner_repo}:workflow:{workflow_path}@{ref}:ref:{ref}"

    # 실제 Fulcio 인증서도 subject DN은 비워두고 신원은 SAN URI로만 담는다.
    subject = issuer_name = x509.Name([])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(subject_uri)]),
            critical=False,
        )
        .add_extension(
            x509.UnrecognizedExtension(FULCIO_OIDC_ISSUER_OID, _der_string(issuer)),
            critical=False,
        )
        .add_extension(
            x509.UnrecognizedExtension(FULCIO_GITHUB_WORKFLOW_REPOSITORY_OID, _der_string(owner_repo)),
            critical=False,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                FULCIO_BUILD_SIGNER_URI_OID,
                _der_string(f"https://github.com/{owner_repo}/{workflow_path}@{ref}"),
            ),
            critical=False,
        )
    )
    return builder.sign(key, hashes.SHA256())


def build_predicate(
    *,
    repository_url: str,
    workflow_path: str,
    commit_sha: str,
    builder_id: str,
) -> dict:
    """predicate_parser.parse_slsa_predicate()가 기대하는 SLSA predicate 구조."""
    return {
        "buildDefinition": {
            "externalParameters": {
                "workflow": {"repository": repository_url, "path": workflow_path},
                "source": {"repository": repository_url},
            },
            "resolvedDependencies": [{"digest": {"gitCommit": commit_sha}}],
        },
        "runDetails": {"builder": {"id": builder_id}},
    }


def build_attestation_response(
    *,
    predicate: dict,
    cert: x509.Certificate,
    log_index: int = 100000,
    integrated_time: int | None = None,
) -> dict:
    """npm attestation API(`/-/npm/v1/attestations/...`) 응답 형태로 조립한다."""
    if integrated_time is None:
        integrated_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": predicate,
    }
    payload_b64 = base64.b64encode(json.dumps(statement).encode("utf-8")).decode("ascii")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    bundle = {
        "dsseEnvelope": {
            "payloadType": "application/vnd.in-toto+json",
            "payload": payload_b64,
            # 서명은 파서가 검증하지 않으므로 형식만 맞춘 더미 값.
            "signatures": [{"keyid": "", "sig": base64.b64encode(b"fake-signature").decode("ascii")}],
        },
        "verificationMaterial": {
            "certificate": {"pem": cert_pem},
            "tlogEntries": [{"logIndex": log_index, "integratedTime": integrated_time}],
        },
    }

    return {
        "attestations": [
            {"predicateType": "https://slsa.dev/provenance/v1", "bundle": bundle}
        ]
    }
