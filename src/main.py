#!/usr/bin/env python3
"""K8s Namespace Auditor — audit Kubernetes namespaces for security issues."""

import argparse
import json
import sys
import os

from auditor import audit_namespace, AuditResult
from llm import explain_audit, check_ollama


def main():
    parser = argparse.ArgumentParser(
        description="Audit Kubernetes namespaces for security issues using AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                # Audit default namespace
  %(prog)s -n production                  # Specify namespace
  %(prog)s --all-namespaces               # Audit all namespaces
  %(prog)s --summary                      # Show summary only (no AI)
  %(prog)s --output json                  # Output as JSON
        """,
    )
    parser.add_argument("-n", "--namespace", default="default",
                        help="Kubernetes namespace")
    parser.add_argument("--all-namespaces", action="store_true",
                        help="Audit all namespaces")
    parser.add_argument("--ollama-url", default="http://localhost:11434",
                        help="Ollama API URL")
    parser.add_argument("--model", default="llama3.2",
                        help="Ollama model to use")
    parser.add_argument("--output", choices=["markdown", "json"],
                        default="markdown", help="Output format")
    parser.add_argument("--summary", action="store_true",
                        help="Show summary only (no AI)")

    args = parser.parse_args()

    # Get namespaces to audit
    if args.all_namespaces:
        namespaces = _get_all_namespaces()
    else:
        namespaces = [args.namespace]

    # Audit each namespace
    all_results = []
    for ns in namespaces:
        print(f"Auditing namespace: {ns}")
        result = audit_namespace(ns)
        all_results.append(result)

    # Show summary
    for result in all_results:
        print(f"\nNamespace: {result.namespace}")
        print(f"  Pods checked: {result.pods_checked}")
        print(f"  Services checked: {result.services_checked}")
        print(f"  Deployments checked: {result.deployments_checked}")
        print(f"  Issues: {len(result.issues)}")
        print(f"    Critical: {result.critical_count}")
        print(f"    High: {result.high_count}")
        print(f"    Medium: {result.medium_count}")
        print(f"    Low: {result.low_count}")

    # Summary mode
    if args.summary:
        for result in all_results:
            print(f"\n{'='*60}")
            print(result.to_prompt())
        return

    # JSON output
    if args.output == "json":
        data = []
        for result in all_results:
            data.append({
                "namespace": result.namespace,
                "pods_checked": result.pods_checked,
                "services_checked": result.services_checked,
                "deployments_checked": result.deployments_checked,
                "issues": [
                    {
                        "severity": i.severity,
                        "category": i.category,
                        "resource_type": i.resource_type,
                        "resource_name": i.resource_name,
                        "description": i.description,
                        "recommendation": i.recommendation,
                    }
                    for i in result.issues
                ],
            })
        print(json.dumps(data, indent=2))
        return

    # Check Ollama
    if not check_ollama(args.ollama_url):
        if not os.environ.get("OPENAI_API_KEY"):
            print("Error: Neither Ollama nor OPENAI_API_KEY available.",
                  file=sys.stderr)
            print("Use --summary to see data without AI.", file=sys.stderr)
            sys.exit(1)

    # Generate AI explanation
    for result in all_results:
        if not result.issues:
            print(f"\n✓ {result.namespace}: No issues found")
            continue

        print(f"\nAnalyzing {result.namespace}...")
        try:
            explanation = explain_audit(result.to_prompt(), args.ollama_url, args.model)
        except ConnectionError as e:
            print(f"Error: {e}", file=sys.stderr)
            continue

        print(explanation)


def _get_all_namespaces() -> list[str]:
    """Get all namespaces."""
    import subprocess

    cmd = ["kubectl", "get", "namespaces", "-o",
           "jsonpath='{.items[*].metadata.name}'"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        return ["default"]

    return result.stdout.strip().strip("'").split()


if __name__ == "__main__":
    main()
