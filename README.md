# Sage
# IAM Validator

Production-grade AWS IAM security scanning tool that detects misconfigurations, privilege escalation paths, and security violations.

## Features

- ✅ Scans all IAM roles and users
- ✅ Detects privilege escalation chains
- ✅ Risk scoring for each finding
- ✅ Actionable remediation recommendations
- ✅ JSON report export
- ✅ Multi-account support

## Quick Start

### Prerequisites
- Python 3.8+
- AWS CLI configured with credentials

### Installation
```bash
git clone https://github.com/SarahModi/iam-validator.git
cd iam-validator
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Usage
```bash
# Scan with default AWS profile
python iam_validator.py

# Scan with specific profile
python iam_validator.py --profile production

# Custom output file
python iam_validator.py --output report.json
```

## Output

Results are saved as JSON with findings and risk scores:
```json
{
  "summary": {
    "total_findings": 5,
    "by_severity": {
      "CRITICAL": 1,
      "HIGH": 2,
      "MEDIUM": 2
    }
  },
  "findings": [...]
}
```

## Rules

Current rules implemented:
- Wildcard actions (*)
- Wildcard resources (*)
- IAM wildcards
- Overprivileged principals
- Admin access on users
- Old access keys
- MFA not enabled
- Root account vulnerabilities

## Contributing

Pull requests welcome!

## License

MIT
