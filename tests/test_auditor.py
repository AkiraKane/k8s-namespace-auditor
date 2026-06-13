"""Tests for K8s namespace auditor."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import pytest
from auditor import SecurityIssue, AuditResult


class TestSecurityIssue:
    def test_defaults(self):
        issue = SecurityIssue(
            severity="critical",
            category="privileged",
            resource_type="Pod",
            resource_name="test-pod",
            namespace="default",
            description="Privileged container",
            recommendation="Remove privileged flag"
        )
        assert issue.severity == "critical"
        assert issue.category == "privileged"


class TestAuditResult:
    def test_empty(self):
        result = AuditResult(namespace="default")
        assert result.critical_count == 0
        assert result.high_count == 0
        assert result.medium_count == 0
        assert result.low_count == 0

    def test_with_issues(self):
        result = AuditResult(namespace="default")
        result.issues = [
            SecurityIssue(
                severity="critical",
                category="privileged",
                resource_type="Pod",
                resource_name="pod1",
                namespace="default",
                description="Privileged",
                recommendation="Fix"
            ),
            SecurityIssue(
                severity="high",
                category="root_user",
                resource_type="Pod",
                resource_name="pod2",
                namespace="default",
                description="Root user",
                recommendation="Fix"
            ),
            SecurityIssue(
                severity="medium",
                category="resource_limits",
                resource_type="Pod",
                resource_name="pod3",
                namespace="default",
                description="No limits",
                recommendation="Fix"
            ),
        ]
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.medium_count == 1

    def test_to_prompt(self):
        result = AuditResult(namespace="production")
        result.pods_checked = 5
        result.issues = [
            SecurityIssue(
                severity="critical",
                category="privileged",
                resource_type="Pod",
                resource_name="test-pod",
                namespace="production",
                description="Privileged container",
                recommendation="Remove privileged flag"
            )
        ]
        prompt = result.to_prompt()
        assert "production" in prompt
        assert "5" in prompt
        assert "CRITICAL" in prompt
        assert "test-pod" in prompt


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
