#!/usr/bin/env python3
import sys
import cvss

# CVSS v3.1
CVSS_DICTIONARY = {
    "AV": {
        "name": "Attack Vector",
        "N": "Network (Remote attack via internet/network path)",
        "A": "Adjacent (Attack requires local network/subnet access)",
        "L": "Local (Attack requires physical access, local shell, or user interaction)",
        "P": "Physical (Attack requires physical interaction with the hardware)"
    },
    "AC": {
        "name": "Attack Complexity",
        "L": "Low (No special conditions required; easily repeatable)",
        "H": "High (Requires specialized conditions, timing, or bypass steps)"
    },
    "PR": {
        "name": "Privileges Required",
        "N": "None (No authentication required to exploit)",
        "L": "Low (Requires standard user/basic privilege authentication)",
        "H": "High (Requires administrative/root level privileges)"
    },
    "UI": {
        "name": "User Interaction",
        "N": "None (Exploit runs completely automatically)",
        "R": "Required (Requires a user to click a link, open a file, or take action)"
    },
    "S": {
        "name": "Scope",
        "U": "Unchanged (Vulnerability only impacts the immediate component)",
        "C": "Changed (Vulnerability can breach sandbox boundaries and affect other systems/components)"
    },
    "C": {
        "name": "Confidentiality",
        "N": "None (No information leakage occurs)",
        "L": "Low (Partial or limited information disclosure)",
        "H": "High (Total information disclosure; all data exposed)"
    },
    "I": {
        "name": "Integrity",
        "N": "None (No data or system modification possible)",
        "L": "Low (Partial/limited modification or unauthorized data alteration)",
        "H": "High (Total data modification; complete loss of system control)"
    },
    "A": {
        "name": "Availability",
        "N": "None (No impact on system availability or performance)",
        "L": "Low (Partial degradation, throttling, or temporary disruption)",
        "H": "High (Total denial of service; resource completely crashes)"
    },
    "E": {
        "name": "Exploit Code Maturity",
        "X": "Not Defined (Skip temporal metric)",
        "U": "Unproven (No functional exploit code exists)",
        "P": "Proof-of-Concept (Exploit code exists but is unreliable/not widely usable)",
        "F": "Functional (Functional exploit code is widely available)",
        "H": "High (Exploit is automated, autonomous, or widely seen in malware)"
    },
    "RL": {
        "name": "Remediation Level",
        "X": "Not Defined (Skip temporal metric)",
        "O": "Official Fix (A complete vendor patch is available)",
        "T": "Temporary Fix (An official workaround or hotfix exists)",
        "W": "Workaround (Unofficial configuration changes or mitigations exist)",
        "U": "Unavailable (No fix or mitigation exists; absolute 0-day)"
    },
    "RC": {
        "name": "Report Confidence",
        "X": "Not Defined (Skip temporal metric)",
        "U": "Unknown (Vague or unconfirmed reports of existence)",
        "R": "Reasonable (Credible details/proofs available, vendor might acknowledge)",
        "C": "Confirmed (Vendor or massive testing confirms the vulnerability)"
    }
}

def analyze_vector():
    if len(sys.argv) < 2:
        print("Usage: python cvss_explainer.py '<VECTOR_STRING>'")
        print("Example: python cvss_explainer.py 'CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C'")
        sys.exit(1)

    vector_str = sys.argv[1]

    try:
        if not vector_str.startswith("CVSS:3"):
            print("Error: This script is explicitly configured for CVSS v3.x vectors.")
            sys.exit(1)

        c = cvss.CVSS3(vector_str)
        severities = c.severities()

        print("=" * 60)
        print(" CVSS METRIC BREAKDOWN & EXPLAINER")
        print("=" * 60)
        print(f"Vector String: {vector_str}\n")
        print(f"Base Score:     {c.base_score:<4} -> [{severities[0]}]")
        print(f"Temporal Score: {c.temporal_score:<4} -> [{severities[1]}]")
        print("-" * 60)
        print(f"{'METRIC':<25} | {'VALUE':<6} | {'DESCRIPTION'}")
        print("-" * 60)

        parts = vector_str.split('/')
        for part in parts:
            if ":" not in part or part.startswith("CVSS"):
                continue

            metric_abbr, value_abbr = part.split(":")
            metric_info = CVSS_DICTIONARY.get(metric_abbr, {})
            metric_name = metric_info.get("name", metric_abbr)
            value_desc = metric_info.get(value_abbr, value_abbr)

            print(f"{metric_name:<25} | {metric_abbr}:{value_abbr:<4} | {value_desc}")

        print("=" * 60)

    except Exception as e:
        print(f"Error parsing vector string: {e}")
        sys.exit(1)

if __name__ == "__main__":
    analyze_vector()
