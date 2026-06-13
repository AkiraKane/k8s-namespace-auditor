"""Kubernetes namespace security auditor."""

import subprocess
import json
from dataclasses import dataclass, field


@dataclass
class SecurityIssue:
    """A security issue found during audit."""
    severity: str  # critical, high, medium, low, info
    category: str  # resource_limits, privileged, network, rbac, etc.
    resource_type: str
    resource_name: str
    namespace: str
    description: str
    recommendation: str


@dataclass
class AuditResult:
    """Audit results for a namespace."""
    namespace: str
    issues: list[SecurityIssue] = field(default_factory=list)
    pods_checked: int = 0
    services_checked: int = 0
    deployments_checked: int = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "low")

    def to_prompt(self) -> str:
        """Convert to prompt for LLM analysis."""
        parts = [
            f"Namespace: {self.namespace}",
            f"Pods checked: {self.pods_checked}",
            f"Services checked: {self.services_checked}",
            f"Deployments checked: {self.deployments_checked}",
            "",
            f"Issues found: {len(self.issues)}",
            f"  Critical: {self.critical_count}",
            f"  High: {self.high_count}",
            f"  Medium: {self.medium_count}",
            f"  Low: {self.low_count}",
            "",
        ]

        # Group by severity
        for severity in ["critical", "high", "medium", "low"]:
            issues = [i for i in self.issues if i.severity == severity]
            if not issues:
                continue

            parts.append(f"## {severity.upper()} ({len(issues)})")
            parts.append("")

            for issue in issues:
                parts.append(f"### {issue.resource_type}/{issue.resource_name}")
                parts.append(f"Category: {issue.category}")
                parts.append(f"Issue: {issue.description}")
                parts.append(f"Recommendation: {issue.recommendation}")
                parts.append("")

        return "\n".join(parts)


def audit_namespace(namespace: str = "default") -> AuditResult:
    """Audit a namespace for security issues."""
    result = AuditResult(namespace=namespace)

    # Audit pods
    pods = _get_pods(namespace)
    result.pods_checked = len(pods)
    for pod in pods:
        _audit_pod(pod, result)

    # Audit deployments
    deployments = _get_deployments(namespace)
    result.deployments_checked = len(deployments)
    for deployment in deployments:
        _audit_deployment(deployment, result)

    # Audit services
    services = _get_services(namespace)
    result.services_checked = len(services)
    for service in services:
        _audit_service(service, result)

    return result


def _get_pods(namespace: str) -> list[dict]:
    """Get all pods in namespace."""
    cmd = ["kubectl", "get", "pods", "-n", namespace, "-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        return []

    try:
        data = json.loads(result.stdout)
        return data.get("items", [])
    except json.JSONDecodeError:
        return []


def _get_deployments(namespace: str) -> list[dict]:
    """Get all deployments in namespace."""
    cmd = ["kubectl", "get", "deployments", "-n", namespace, "-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        return []

    try:
        data = json.loads(result.stdout)
        return data.get("items", [])
    except json.JSONDecodeError:
        return []


def _get_services(namespace: str) -> list[dict]:
    """Get all services in namespace."""
    cmd = ["kubectl", "get", "services", "-n", namespace, "-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        return []

    try:
        data = json.loads(result.stdout)
        return data.get("items", [])
    except json.JSONDecodeError:
        return []


def _audit_pod(pod: dict, result: AuditResult):
    """Audit a single pod."""
    name = pod.get("metadata", {}).get("name", "unknown")
    namespace = pod.get("metadata", {}).get("namespace", result.namespace)

    # Check for privileged containers
    for container in pod.get("spec", {}).get("containers", []):
        container_name = container.get("name", "unknown")

        # Check security context
        security_context = container.get("securityContext", {})
        if security_context.get("privileged"):
            result.issues.append(SecurityIssue(
                severity="critical",
                category="privileged",
                resource_type="Pod",
                resource_name=f"{name}/{container_name}",
                namespace=namespace,
                description="Container running in privileged mode",
                recommendation="Remove privileged: true, use specific capabilities instead"
            ))

        if security_context.get("runAsUser") == 0:
            result.issues.append(SecurityIssue(
                severity="high",
                category="root_user",
                resource_type="Pod",
                resource_name=f"{name}/{container_name}",
                namespace=namespace,
                description="Container running as root user",
                recommendation="Set runAsUser to non-root user (e.g., 1000)"
            ))

        # Check resource limits
        resources = container.get("resources", {})
        if not resources.get("limits"):
            result.issues.append(SecurityIssue(
                severity="medium",
                category="resource_limits",
                resource_type="Pod",
                resource_name=f"{name}/{container_name}",
                namespace=namespace,
                description="No resource limits defined",
                recommendation="Add CPU and memory limits to prevent resource exhaustion"
            ))

        if not resources.get("requests"):
            result.issues.append(SecurityIssue(
                severity="low",
                category="resource_requests",
                resource_type="Pod",
                resource_name=f"{name}/{container_name}",
                namespace=namespace,
                description="No resource requests defined",
                recommendation="Add CPU and memory requests for proper scheduling"
            ))

    # Check for host network (pod-level field, checked once per pod)
    if pod.get("spec", {}).get("hostNetwork"):
        result.issues.append(SecurityIssue(
            severity="high",
            category="host_network",
            resource_type="Pod",
            resource_name=name,
            namespace=namespace,
            description="Pod using host network",
            recommendation="Remove hostNetwork: true unless absolutely necessary"
        ))

    # Check for host PID (pod-level field, checked once per pod)
    if pod.get("spec", {}).get("hostPID"):
        result.issues.append(SecurityIssue(
            severity="high",
            category="host_pid",
            resource_type="Pod",
            resource_name=name,
            namespace=namespace,
            description="Pod using host PID namespace",
            recommendation="Remove hostPID: true unless absolutely necessary"
        ))


def _audit_deployment(deployment: dict, result: AuditResult):
    """Audit a single deployment."""
    name = deployment.get("metadata", {}).get("name", "unknown")
    namespace = deployment.get("metadata", {}).get("namespace", result.namespace)

    # Check for missing health checks
    template = deployment.get("spec", {}).get("template", {})
    for container in template.get("spec", {}).get("containers", []):
        container_name = container.get("name", "unknown")

        if not container.get("livenessProbe"):
            result.issues.append(SecurityIssue(
                severity="low",
                category="health_checks",
                resource_type="Deployment",
                resource_name=f"{name}/{container_name}",
                namespace=namespace,
                description="No liveness probe defined",
                recommendation="Add livenessProbe to detect and restart unhealthy containers"
            ))

        if not container.get("readinessProbe"):
            result.issues.append(SecurityIssue(
                severity="low",
                category="health_checks",
                resource_type="Deployment",
                resource_name=f"{name}/{container_name}",
                namespace=namespace,
                description="No readiness probe defined",
                recommendation="Add readinessProbe to prevent traffic to unready containers"
            ))

    # Check replica count
    replicas = deployment.get("spec", {}).get("replicas", 1)
    if replicas == 1:
        result.issues.append(SecurityIssue(
            severity="info",
            category="availability",
            resource_type="Deployment",
            resource_name=name,
            namespace=namespace,
            description="Single replica deployment (no high availability)",
            recommendation="Consider increasing replicas for production workloads"
        ))


def _audit_service(service: dict, result: AuditResult):
    """Audit a single service."""
    name = service.get("metadata", {}).get("name", "unknown")
    namespace = service.get("metadata", {}).get("namespace", result.namespace)

    # Check for NodePort services
    service_type = service.get("spec", {}).get("type", "")
    if service_type == "NodePort":
        result.issues.append(SecurityIssue(
            severity="medium",
            category="exposure",
            resource_type="Service",
            resource_name=name,
            namespace=namespace,
            description="Service exposed via NodePort",
            recommendation="Consider using ClusterIP with Ingress instead"
        ))

    # Check for LoadBalancer without restrictions
    if service_type == "LoadBalancer":
        annotations = service.get("metadata", {}).get("annotations", {})
        if not any("whitelist" in k.lower() or "allowed" in k.lower()
                   for k in annotations.keys()):
            result.issues.append(SecurityIssue(
                severity="medium",
                category="exposure",
                resource_type="Service",
                resource_name=name,
                namespace=namespace,
                description="LoadBalancer service without IP restrictions",
                recommendation="Add loadBalancerSourceRanges to restrict access"
            ))
