import sys
import os
sys.path.insert(0, os.path.expanduser("~/projects/Collector/src"))

from fake_attestation import make_fake_fulcio_cert, build_predicate, build_attestation_response

from rootkeepers.collectors.sigstore.bundle_parser import extract_predicate_from_dsse
from rootkeepers.collectors.sigstore.predicate_parser import parse_slsa_predicate
from rootkeepers.collectors.sigstore.oidc_parser import parse_fulcio_oidc_info
from rootkeepers.collectors.sigstore.cross_validator import validate_oidc_matches_predicate
from rootkeepers.collectors.sigstore.rekor_parser import parse_rekor_log_info

OWNER_REPO = "minjae0202/orphan-test"
WORKFLOW = ".github/workflows/release.yml"
COMMIT = "a" * 40

cert = make_fake_fulcio_cert(owner_repo=OWNER_REPO, workflow_path=WORKFLOW)
predicate = build_predicate(
    repository_url=f"https://github.com/{OWNER_REPO}",
    workflow_path=WORKFLOW,
    commit_sha=COMMIT,
    builder_id="https://github.com/actions/runner/github-hosted",
)
response = build_attestation_response(predicate=predicate, cert=cert)

bundle = response["attestations"][0]["bundle"]
parsed_predicate_raw = extract_predicate_from_dsse(bundle)
predicate_info = parse_slsa_predicate(parsed_predicate_raw)
oidc_info = parse_fulcio_oidc_info(bundle["verificationMaterial"])
rekor_info = parse_rekor_log_info(bundle["verificationMaterial"])
validation = validate_oidc_matches_predicate(predicate_info, oidc_info)

print("=== predicate_info ===")
print(predicate_info)
print("\n=== oidc_info ===")
print(oidc_info)
print("\n=== rekor_info ===")
print(rekor_info)
print("\n=== cross-validation ===")
print(validation)
