# Config rulesets

Organizational policy checks for configuration files.

| Ruleset | File | What it checks |
|---------|------|----------------|
| Kubernetes Pod | `kubernetes-pod.json` | Required labels, resource limits, no privileged containers, image pinning (no :latest) |
| GitHub Actions | `github-actions.json` | Workflow name/trigger, explicit permissions, job runs-on/steps/timeout |

## Usage

Convert YAML configs to JSON first (scheck auto-detects YAML input):

```
$ scheck validate deployment.yaml --rules rulesets/config/kubernetes-pod.json
$ scheck validate workflow.json --rules rulesets/config/github-actions.json
```

## Test fixtures

Test data lives under `etc/testdata/config/`.
