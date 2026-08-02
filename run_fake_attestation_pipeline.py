"""가짜 Sigstore attestation을 주입해서 Collector 파이프라인을 검증하는 스크립트.

Collector 소스코드는 전혀 수정하지 않는다. requests.get을 두 지점에서
가로챈다:
  1. npm 패키지 메타데이터 요청 -> 실제 Verdaccio 응답을 받아온 뒤,
     ATTESTATION_CONFIG에 정의된 버전에 대해 dist.attestations 필드를 주입한다.
  2. npm attestation API 요청 -> ATTESTATION_CONFIG에 정의된 버전이면
     fake_attestation.py로 만든 가짜 bundle을 그대로 반환한다.
"""
import sys
import os
sys.path.insert(0, os.path.expanduser("~/projects/Collector/src"))

import json
import urllib.parse
import requests

from fake_attestation import make_fake_fulcio_cert, build_predicate, build_attestation_response

_original_get = requests.get

REPO = "minjae0202/orphan-test"
GOOD_WORKFLOW = ".github/workflows/release.yml"
GOOD_BUILDER = "https://github.com/actions/runner/github-hosted"

# 버전별로 어떤 attestation을 서빙할지 정의. commit_sha는 각 버전의 실제
# gitHead와 맞출 필요 없음 (predicate_parser가 뽑아내는 값일 뿐, 별도 검증 없음).
def _good(commit_byte: str) -> dict:
    """정상 baseline용: 저장소/워크플로/builder가 전부 일관된 attestation."""
    return dict(
        owner_repo=REPO,
        cert_workflow=GOOD_WORKFLOW,
        predicate_repo=f"https://github.com/{REPO}",
        predicate_workflow=GOOD_WORKFLOW,
        builder_id=GOOD_BUILDER,
        commit=commit_byte * 40,
    )


ATTESTATION_CONFIG = {
    "3.0.0": dict(
        owner_repo="attacker-org/evil-repo",       # 인증서(OIDC)는 다른 저장소를 주장
        cert_workflow=".github/workflows/steal.yml",
        predicate_repo=f"https://github.com/{REPO}",  # predicate는 우리 저장소라고 주장
        predicate_workflow=GOOD_WORKFLOW,
        builder_id=GOOD_BUILDER,
        commit="b" * 40,
    ),
    # 규칙 5(Unexpected Builder) 기준선용 정상 릴리스들
    "1.0.4": _good("4"),
    "1.0.5": _good("5"),
    "1.0.6": _good("6"),
    "1.0.7": _good("7"),
    # 규칙 5 변조 버전: 저장소/워크플로는 기준선과 동일(그래서 oidc_mismatch는
    # 안 뜸), builder만 평소와 다른 비공식 러너로 바뀜.
    "3.1.0": dict(
        owner_repo=REPO,
        cert_workflow=GOOD_WORKFLOW,
        predicate_repo=f"https://github.com/{REPO}",
        predicate_workflow=GOOD_WORKFLOW,
        builder_id="https://gitlab.com/self-hosted-runner/unofficial",
        commit="c" * 40,
    ),
}


def _fake_response(status_code: int, payload: dict) -> requests.Response:
    resp = requests.Response()
    resp.status_code = status_code
    resp._content = json.dumps(payload).encode("utf-8")
    resp.headers["Content-Type"] = "application/json"
    return resp


def _build_attestation_payload(version: str) -> dict:
    cfg = ATTESTATION_CONFIG[version]
    cert = make_fake_fulcio_cert(owner_repo=cfg["owner_repo"], workflow_path=cfg["cert_workflow"])
    predicate = build_predicate(
        repository_url=cfg["predicate_repo"],
        workflow_path=cfg["predicate_workflow"],
        commit_sha=cfg["commit"],
        builder_id=cfg["builder_id"],
    )
    return build_attestation_response(predicate=predicate, cert=cert)


def patched_get(url, *args, **kwargs):
    if url.startswith("https://registry.npmjs.org/-/npm/v1/attestations/"):
        spec = urllib.parse.unquote(url.rsplit("/", 1)[-1])  # "orphan-test@3.0.0"
        _, _, version = spec.rpartition("@")
        if version in ATTESTATION_CONFIG:
            return _fake_response(200, _build_attestation_payload(version))
        return _fake_response(404, {"message": "no attestations for this version"})

    if url.startswith("https://registry.npmjs.org/"):
        redirected = "http://localhost:4873/" + url[len("https://registry.npmjs.org/"):]
        response = _original_get(redirected, *args, **kwargs)
        if response.status_code == 200 and "/-/" not in url:
            try:
                data = response.json()
            except ValueError:
                return response
            versions = data.get("versions", {})
            for version, version_data in versions.items():
                if version in ATTESTATION_CONFIG and isinstance(version_data, dict):
                    version_data.setdefault("dist", {})["attestations"] = {
                        "url": f"https://registry.npmjs.org/-/npm/v1/attestations/{data.get('name')}@{version}",
                        "provenance": {"predicateType": "https://slsa.dev/provenance/v1"},
                    }
            response._content = json.dumps(data).encode("utf-8")
        return response

    return _original_get(url, *args, **kwargs)


requests.get = patched_get

from rootkeepers.interceptor.lineage import collect_release_lineage_report, evaluate_risk
from rootkeepers.interceptor.detailed_rule_engine import evidence_from_lineage, evaluate_detailed_evidence


def run(package_name: str, version: str):
    report = collect_release_lineage_report(package_name, version)
    print("=== Track statuses ===")
    print(json.dumps(report.get("summary", {}), indent=2, ensure_ascii=False))

    sigstore_track = report.get("tracks", {}).get("sigstore", {})
    print("\n=== Sigstore track ===")
    print(json.dumps(sigstore_track, indent=2, ensure_ascii=False)[:2500])

    print("\n=== evaluate_risk() ===")
    print(json.dumps(evaluate_risk(report), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    package_name = sys.argv[1] if len(sys.argv) > 1 else "orphan-test"
    version = sys.argv[2] if len(sys.argv) > 2 else "3.0.0"
    run(package_name, version)
