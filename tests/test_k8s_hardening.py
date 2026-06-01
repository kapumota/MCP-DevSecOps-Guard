from pathlib import Path


def test_kubernetes_manifest_has_runtime_hardening():
    text = Path("k8s/deployment.yaml").read_text(encoding="utf-8")

    required_fragments = [
        "runAsNonRoot: true",
        "runAsUser: 1000",
        "allowPrivilegeEscalation: false",
        "readOnlyRootFilesystem: true",
        "capabilities:",
        "- ALL",
        "seccompProfile:",
        "type: RuntimeDefault",
        "resources:",
        "limits:",
        "readinessProbe:",
        "path: /ready",
        "livenessProbe:",
        "path: /health",
        "kind: NetworkPolicy",
    ]
    for fragment in required_fragments:
        assert fragment in text
