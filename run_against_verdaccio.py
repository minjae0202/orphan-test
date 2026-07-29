import sys
import os
sys.path.insert(0, os.path.expanduser("~/projects/Collector/src"))

import requests

_original_get = requests.get


def patched_get(url, *args, **kwargs):
    if url.startswith("https://registry.npmjs.org/"):
        package_part = url.replace("https://registry.npmjs.org/", "")
        url = f"http://localhost:4873/{package_part}"
    return _original_get(url, *args, **kwargs)


requests.get = patched_get

from rootkeepers.collectors.npm.crawler import (
    fetch_package_data,
    collect_package_metadata,
    collect_artifact_info,
    collect_attestation_status,
)
from rootkeepers.collectors.github.github_collector import get_repo, collect_commit


def run(package_name: str, owner_repo: str, version: str | None = None):
    raw_data = fetch_package_data(package_name)
    if raw_data is None:
        print("Track A: npm 조회 실패")
        return

    latest_version = version or raw_data.get("dist-tags", {}).get("latest")
    version_data = raw_data.get("versions", {}).get(latest_version, {})

    metadata = collect_package_metadata(raw_data, latest_version)
    artifact = collect_artifact_info(version_data)
    attestation = collect_attestation_status(version_data)

    print(f"=== Track A: npm ({package_name}@{latest_version}) ===")
    print("published_at:", metadata["published_at"])
    print("gitHead     :", artifact["git_head"])
    print("repo_url    :", artifact["repo_url"])
    print("attestation :", attestation)

    git_head = artifact["git_head"]
    print(f"\n=== Track B: GitHub ({owner_repo}) ===")
    if not git_head:
        print("gitHead 없음 - GitHub 조회 스킵")
        return

    g, repo = get_repo(owner_repo)
    commit_info = collect_commit(repo, git_head)
    if commit_info is None:
        print(f"결과: gitHead({git_head})가 GitHub에 존재하지 않음 -> ORPHAN / RISK")
    else:
        print(f"결과: gitHead({git_head})가 GitHub에 존재함 -> PASS")
        print(commit_info)


if __name__ == "__main__":
    package_name = sys.argv[1] if len(sys.argv) > 1 else "orphan-test"
    owner_repo = sys.argv[2] if len(sys.argv) > 2 else "minjae0202/orphan-test"
    version = sys.argv[3] if len(sys.argv) > 3 else None
    run(package_name, owner_repo, version)
