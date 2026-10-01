"""
PROJECT: MULTI-VENDOR INFRASTRUCTURE COMPLIANCE ENGINE
AUTHOR: MATUTUZELA JABULANI NDLOVU
PURPOSE: Audits Cisco/Mikrotik config files against defined security matrices.
         Combines dynamic regex parsing, validation logic, and JSON telemetry reporting.
"""

import yaml
import json
import re
import sys
import os

def load_audit_rules(rules_path="rules.yaml"):
    """
    Loads compliance criteria with strict error tracking.
    """
    if not os.path.exists(rules_path):
        print(f"❌ Structural Error: Configuration matrix file '{rules_path}' is missing.")
        sys.exit(1)
        
    try:
        with open(rules_path, "r", encoding="utf-8") as file:
            return yaml.safe_load(file)
    except yaml.YAMLError as exc:
        print(f"❌ Syntax Error: Failed to parse '{rules_path}'. Details: {exc}")
        sys.exit(1)

def normalize_line(line):
    """
    Normalizes configuration strings by converting them to lowercase and 
    collapsing multiple spaces to handle vendor indentation inconsistencies.
    """
    return " ".join(line.lower().split())

def audit_config_file(config_path, vendor_type, rules):
    """
    Evaluates raw configuration text dumps against global security standards
    and outputs a structured pipeline JSON report.
    """
    if vendor_type not in rules:
        print(f"❌ Framework Error: Vendor profile '{vendor_type}' is not defined in rules.yaml.")
        return False

    if not os.path.exists(config_path):
        print(f"💡 Execution Hint: '{config_path}' not found. Create this file to run a live test loop.")
        return False

    # Read configuration file safely handling typical network log text encodings
    try:
        with open(config_path, "r", encoding="utf-8", errors="ignore") as file:
            raw_text = file.read()
    except Exception as e:
        print(f"❌ Operating System Error: Unable to read {config_path}. Details: {e}")
        return False

    # Split lines and clean for matrix scanning
    raw_lines = raw_text.splitlines()
    normalized_config = [normalize_line(line) for line in raw_lines if line.strip()]
    
    # 1. Dynamic Hostname Extraction (Ported from legacy script)
    hostname = "Unknown-Device"
    hostname_match = re.search(r"hostname\s+(\S+)", raw_text, re.IGNORECASE)
    if hostname_match:
        hostname = hostname_match.group(1)

    vendor_rules = rules[vendor_type]
    
    # Structure the programmatic telemetry payload (Ported from legacy script)
    audit_report = {
        "device_hostname": hostname,
        "vendor_platform": vendor_type,
        "target_source_file": config_path,
        "vulnerabilities_detected": [],
        "passed_compliance_checks": []
    }

    # 2. Audit Forbidden Rules (Detecting security vulnerabilities)
    for forbidden in vendor_rules.get("forbidden_commands", []):
        normalized_forbidden = normalize_line(forbidden)
        breach_found = any(normalized_forbidden in norm_line for norm_line in normalized_config)
        
        if breach_found:
            audit_report["vulnerabilities_detected"].append(f"Forbidden command active: '{forbidden}'")
        else:
            audit_report["passed_compliance_checks"].append(f"Clear of forbidden command: '{forbidden}'")

    # 3. Audit Mandatory Rules (Detecting missing baseline defenses)
    for mandatory in vendor_rules.get("mandatory_commands", []):
        normalized_mandatory = normalize_line(mandatory)
        match_found = any(normalized_mandatory in norm_line for norm_line in normalized_config)
        
        if not match_found:
            audit_report["vulnerabilities_detected"].append(f"Missing required baseline defense: '{mandatory}'")
        else:
            audit_report["passed_compliance_checks"].append(f"Verified mandatory baseline: '{mandatory}'")

    # Final execution status output
    print(f"\n🔍 Executing Enterprise Compliance Audit for {hostname}...")
    print("=" * 70)
    
    # Output results as a clean, standardized JSON string for data pipelines
    print(json.dumps(audit_report, indent=4))
    print("=" * 70)

    return len(audit_report["vulnerabilities_detected"]) == 0

if __name__ == "__main__":
    # Standard entry point execution loop
    rules_matrix = load_audit_rules()
    
    # Defaults to look for local backup files. 
    # Create a quick local 'cisco_backup.txt' to watch it parse live data.
    audit_config_file("cisco_backup.txt", "cisco_ios", rules_matrix)
