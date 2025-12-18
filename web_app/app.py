from flask import Flask, render_template, request, jsonify
import subprocess
import json
import os
import tempfile
import sys

# Add parent directory to path so we can import Sage modules
sys.path.append('..')

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Run Sage scan with provided AWS credentials."""
    access_key = request.form.get('access_key', '').strip()
    secret_key = request.form.get('secret_key', '').strip()
    region = request.form.get('region', 'us-east-1')
    
    if not access_key or not secret_key:
        return jsonify({'error': 'Please provide both Access Key and Secret Key'}), 400
    
    try:
        print(f"🔍 Starting scan for key: {access_key[:10]}...")
        
        # Create temporary credentials file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(f"""[default]
aws_access_key_id={access_key}
aws_secret_access_key={secret_key}
region={region}
output=json""")
            creds_file = f.name
        
        # Set environment for boto3
        original_env = os.environ.copy()
        os.environ['AWS_SHARED_CREDENTIALS_FILE'] = creds_file
        
        # Change to parent directory to run Sage
        original_dir = os.getcwd()
        os.chdir('..')
        
        # Run Sage scan (using your existing iam_validator.py)
        result = subprocess.run(
            ['python', 'iam_validator.py', '--profile', 'default', '--output', 'web_scan_result.json'],
            capture_output=True,
            text=True,
            timeout=180  # 3 minute timeout
        )
        
        # Check if scan was successful
        if result.returncode != 0:
            error_msg = result.stderr if result.stderr else "Scan failed with unknown error"
            return jsonify({'error': error_msg}), 500
        
        # Read the results
        results_file = 'web_scan_result.json'
        if os.path.exists(results_file):
            with open(results_file, 'r') as f:
                findings = json.load(f)
            os.remove(results_file)  # Clean up
        else:
            # Try to parse output directly
            findings = {'summary': {'total_findings': 0}, 'findings': []}
        
        # Restore original directory and environment
        os.chdir(original_dir)
        os.environ.clear()
        os.environ.update(original_env)
        
        # Clean up credentials file
        os.unlink(creds_file)
        
        return jsonify(findings)
        
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Scan timed out after 3 minutes'}), 500
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
