"""
Report Generator - Output formatting
"""

import json
from typing import Dict, List
from datetime import datetime


class ReportGenerator:
    """Generate findings in multiple formats."""
    
    @staticmethod
    def generate_summary(findings: List[Dict]) -> Dict:
        """Create summary statistics."""
        summary = {
            'timestamp': datetime.now().isoformat(),
            'total_findings': len(findings),
            'by_severity': {
                'CRITICAL': len([f for f in findings if f['severity'] == 'CRITICAL']),
                'HIGH': len([f for f in findings if f['severity'] == 'HIGH']),
                'MEDIUM': len([f for f in findings if f['severity'] == 'MEDIUM']),
                'LOW': len([f for f in findings if f['severity'] == 'LOW'])
            },
            'by_type': {}
        }
        
        for finding in findings:
            ftype = finding['type']
            if ftype not in summary['by_type']:
                summary['by_type'][ftype] = 0
            summary['by_type'][ftype] += 1
        
        return summary
    
    @staticmethod
    def print_summary(findings: List[Dict]):
        """Print pretty summary to console."""
        summary = ReportGenerator.generate_summary(findings)
        
        print("\n" + "="*70)
        print("IAM VALIDATOR - SECURITY REPORT".center(70))
        print("="*70)
        print(f"\n📊 SUMMARY")
        print(f"   Total Findings: {summary['total_findings']}")
        print(f"   🔴 CRITICAL: {summary['by_severity']['CRITICAL']}")
        print(f"   🟠 HIGH: {summary['by_severity']['HIGH']}")
        print(f"   🟡 MEDIUM: {summary['by_severity']['MEDIUM']}")
        print(f"   🟢 LOW: {summary['by_severity']['LOW']}")
        
        print(f"\n🔍 FINDINGS BY TYPE")
        for ftype, count in sorted(summary['by_type'].items()):
            print(f"   {ftype}: {count}")
        
        print("\n" + "="*70 + "\n")
    
    @staticmethod
    def export_json(findings: List[Dict], filename: str = 'iam_findings.json'):
        """Export findings to JSON."""
        summary = ReportGenerator.generate_summary(findings)
        output = {
            'summary': summary,
            'findings': findings
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"✅ Report saved to {filename}")
