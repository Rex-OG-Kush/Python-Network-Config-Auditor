import yaml
import sys

def load_audit_rules(rules_path="rules.yaml"):
    """Loads the compliance rule matrix from the YAML schema."""
    with open(rules_path, "r") as file:
        return yaml.safe_load(file)

def audit_config_file(config_path, vendor_type, rules):
    """Parses a configuration file against vendor-specific compliance definitions."""
    if vendor_type not in rules:
        print(f"❌ Error: Vendor profile '{vendor_type}' not found in rules matrix.")
        return False

    # Read the target network backup file
    with open(config_path, "r") as file:
        config_lines = [line.strip() for line in file.readlines()]

    vendor_rules = rules[vendor_type]
    passed_audit = True
    print(f"\n🔍 Starting Security Audit for {vendor_type} ({config_path})...")
    print("=" * 60)

    # Check for Forbidden Strings (Security Vulnerabilities)
    for forbidden in vendor_rules.get("forbidden_commands", []):
        for line in config_lines:
            if forbidden in line:
                print(f"🚨 SECURITY FAULT: Found forbidden command configuration -> '{line}'")
                passed_audit = False

    # Check for Mandatory Strings (Security Baselines)
    for mandatory in vendor_rules.get("mandatory_commands", []):
        found = any(mandatory in line for line in config_lines)
        if not found:
            print(f"🚨 COMPLIANCE FAULT: Missing required configuration -> '{mandatory}'")
            passed_audit = False

    if passed_audit:
        print("✅ SUCCESS: Device configuration matches all global security compliance baselines.")
    else:
        print("\n❌ FAILED: Configuration audit exposed critical vulnerabilities. Remediation required.")
    
    return passed_audit

if __name__ == "__main__":
    # Load rules and run a test execution against a simulated configuration block
    rules_matrix = load_audit_rules()
    
    # Example: Simulating a check against a Cisco backup file
    # In practice, replace 'cisco_backup.txt' with your actual router configuration exports
    try:
        audit_config_file("cisco_backup.txt", "cisco_ios", rules_matrix)
    except FileNotFoundError:
        print("💡 Setup Note: Please add a router backup file (e.g., 'cisco_backup.txt') to test the script live.")
