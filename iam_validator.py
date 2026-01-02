"""
IAM Validator - Main orchestrator
Production-grade AWS IAM security scanning tool
"""
import argparse
from aws_client import AWSClient
from validator_engine import ValidationEngine
from report_generator import ReportGenerator
class IAMValidator:
    """Main orchestrator - brings everything together."""

    def __init__(self, aws_profile: str):
        self.aws_client = AWSClient(aws_profile)
        self.validator = ValidationEngine(aws_client=self.aws_client)  # ← Pass aws_client

    def run_full_scan(self):
        """Execute complete scan."""
        print("\n" + "="*70)
        print("IAM VALIDATOR - STARTING FULL SCAN".center(70))
        print("="*70 + "\n")

        roles = self.aws_client.get_all_roles()
        users = self.aws_client.get_all_users()
        root_data = self.aws_client.check_root_account()

        findings = self.validator.validate_all(roles, users, root_data)

        ReportGenerator.print_summary(findings)
        ReportGenerator.export_json(findings)

        return findings
def main():
    parser = argparse.ArgumentParser(description='IAM Validator - AWS IAM Security Scanner')
    parser.add_argument('--profile', default='default', help='AWS profile to use')
    parser.add_argument('--output', default='iam_findings.json', help='Output file')

    args = parser.parse_args()

    try:
        validator = IAMValidator(args.profile)
        findings = validator.run_full_scan()

        print("\n✅ Scan complete!")
        print(f"📁 Results saved to: {args.output}")

    except KeyboardInterrupt:
        print("\n\n⚠️  Scan cancelled by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        raise
if __name__ == '__main__':
    main()
