# Sage

**Enterprise AWS IAM Security Scanner**

Production-grade AWS IAM security scanning tool that detects misconfigurations, privilege escalation paths, and security violations.

## Features

- ✅ **Comprehensive Scanning** - All IAM roles, users, and policies
- ✅ **Risk Intelligence** - Priority scoring for each finding
- ✅ **Actionable Insights** - Clear remediation steps
- ✅ **Multiple Formats** - JSON, console, and HTML reports
- ✅ **Enterprise Ready** - Multi-account, multi-region support

## Quick Start

### Prerequisites
- Python 3.8+
- AWS CLI configured with credentials

### Installation
```bash
git clone https://github.com/SarahModi/Sage.git
cd Sage
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```


### AWS Setup
Option 1: Environment Variables
```bash
export AWS_ACCESS_KEY_ID="your_access_key"
export AWS_SECRET_ACCESS_KEY="your_secret_key"
export AWS_DEFAULT_REGION="us-east-1"
```
Option 2: AWS Credentials File
```bash
mkdir -p ~/.aws
nano ~/.aws/credentials
[default]
aws_access_key_id = your_access_key
aws_secret_access_key = your_secret_key

nano ~/.aws/config 
[default]
region = us-east-1
```

### Usage
```bash
# Basic scan with default AWS profile
python iam_validator.py

# Scan with specific AWS profile
python iam_validator.py --profile production

# Custom output file
python iam_validator.py --output security_report.json

# Generate credential report first (for root account checks)
aws iam generate-credential-report
```

 Output
======================================================================
                   SAGE - SECURITY REPORT                    
======================================================================
📊 SUMMARY
   Total Findings: 2
   🔴 CRITICAL: 1
   🟠 HIGH: 1
   🟡 MEDIUM: 0
   🟢 LOW: 0

## JSON Report (iam_findings.json):
```bash
{
  "summary": {
    "timestamp": "2024-01-15T10:30:00",
    "total_findings": 2,
    "by_severity": {
      "CRITICAL": 1,
      "HIGH": 1,
      "MEDIUM": 0,
      "LOW": 0
    }
  },
  "findings": [
    {
      "type": "ROOT_MFA_DISABLED",
      "severity": "CRITICAL",
      "risk_score": 90,
      "resource": "<root>",
      "message": "MFA not enabled on root account",
      "fix": "Enable MFA on root account via AWS Console"
    }
  ]
}
```

### Security Rules

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
