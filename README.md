# K8s Namespace Auditor 🔍🤖

A CLI tool that audits Kubernetes namespaces for security issues and uses AI to explain findings and suggest fixes. Helps maintain security posture and compliance.

## What It Does

1. **Scans** namespaces for security issues
2. **Detects** privileged containers, missing resource limits, root users
3. **Explains** findings using AI (Ollama)
4. **Suggests** specific fixes with YAML snippets

## Quick Start

```bash
# Audit default namespace
python src/main.py

# Specify namespace
python src/main.py -n production

# Audit all namespaces
python src/main.py --all-namespaces

# Summary only (no AI)
python src/main.py --summary

# Output as JSON
python src/main.py --output json
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   kubectl       │────▶│    Auditor      │────▶│   LLM Client    │
│   (K8s API)     │     │  (rules)        │     │   (Ollama)      │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                              │                         │
                              ▼                         ▼
                        ┌─────────────────┐     ┌─────────────────┐
                        │  AuditResult    │────▶│   Explanation   │
                        │  (structured)   │     │   (markdown)    │
                        └─────────────────┘     └─────────────────┘
```

## Example

```bash
$ python src/main.py -n production

Auditing namespace: production

Namespace: production
  Pods checked: 12
  Services checked: 5
  Deployments checked: 4
  Issues: 8
    Critical: 1
    High: 3
    Medium: 2
    Low: 2

## CRITICAL (1)

### Pod/api-server/app
Category: privileged
Issue: Container running in privileged mode
Recommendation: Remove privileged: true, use specific capabilities instead

## HIGH (3)

### Pod/worker/root
Category: root_user
Issue: Container running as root user
Recommendation: Set runAsUser to non-root user (e.g., 1000)
```

## Security Checks

| Category | Severity | Description |
|----------|----------|-------------|
| Privileged | Critical | Container running in privileged mode |
| Root User | High | Container running as root |
| Host Network | High | Pod using host network |
| Host PID | High | Pod using host PID namespace |
| Resource Limits | Medium | No CPU/memory limits defined |
| NodePort | Medium | Service exposed via NodePort |
| LoadBalancer | Medium | LoadBalancer without IP restrictions |
| Health Checks | Low | Missing liveness/readiness probes |
| Resource Requests | Low | No resource requests defined |
| Single Replica | Info | No high availability |

## Requirements

- Python 3.11+
- kubectl configured (access to a cluster)
- Ollama running locally (or OPENAI_API_KEY)

## Installation

```bash
git clone https://github.com/AkiraKane/k8s-namespace-auditor.git
cd k8s-namespace-auditor
```

## Docker

```bash
docker build -t k8s-namespace-auditor .
docker run -v ~/.kube:/root/.kube:ro k8s-namespace-auditor python main.py --summary
```

## Interview Talking Points

- **Security Posture**: Automates security auditing of K8s clusters
- **Compliance**: Helps meet SOC2, PCI-DSS, HIPAA requirements
- **Shift Left**: Catches issues before they reach production
- **AI Explanation**: Makes security accessible to developers

## License

MIT
