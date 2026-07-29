import sys
import os
sys.path.insert(0, os.path.expanduser("~/projects/Collector/src"))

import json
import requests

_original_get = requests.get


def patched_get(url, *args, **kwargs):
    if url.startswith("https://registry.npmjs.org/"):
        package_part = url.replace("https://registry.npmjs.org/", "")
        url = f"http://localhost:4873/{package_part}"
    return _original_get(url, *args, **kwargs)


requests.get = patched_get

from rootkeepers.interceptor.lineage import collect_release_lineage_report, evaluate_risk
from rootkeepers.interceptor.detailed_rule_engine import (
    evidence_from_lineage,
    evaluate_detailed_evidence,
)


def run(package_name: str, version: str):
    report = collect_release_lineage_report(package_name, version)

    print("=== Track statuses ===")
    print(json.dumps(report.get("summary", {}), indent=2, ensure_ascii=False))

    github_track = report.get("tracks", {}).get("github", {})
    print("\n=== GitHub track (commit lookup) ===")
    print(json.dumps(github_track, indent=2, ensure_ascii=False)[:2000])

    print("\n=== evaluate_risk() (현재 main에 실제로 연결된 임시 판정 로직) ===")
    verdict = evaluate_risk(report)
    print(json.dumps(verdict, indent=2, ensure_ascii=False))

    print("\n=== detailed_rule_engine (아직 파이프라인에 연결 안 된 규칙 엔진, 참고용) ===")
    evidence = evidence_from_lineage(report)
    detailed = evaluate_detailed_evidence(evidence)
    print(json.dumps(detailed, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    package_name = sys.argv[1] if len(sys.argv) > 1 else "orphan-test"
    version = sys.argv[2] if len(sys.argv) > 2 else "1.0.4"
    run(package_name, version)
