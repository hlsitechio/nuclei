from flask import Flask, request, jsonify
import subprocess
import shlex
import os
import json
import re

app = Flask(__name__)

TEMPLATES_PATH = '/root/nuclei-templates'

@app.route('/scan', methods=['POST'])
def scan():
    """Full nuclei scan with custom options"""
    data = request.json or {}
    target = data.get('target', '')
    templates = data.get('templates', '')  # e.g., "cves,vulnerabilities"
    tags = data.get('tags', '')  # e.g., "xss,sqli,rce"
    severity = data.get('severity', '')  # e.g., "critical,high"
    args = data.get('args', '')

    if not target:
        return jsonify({'error': 'target required'}), 400

    # Build command
    cmd = ['nuclei', '-u', target, '-json-export', '/tmp/results.json', '-silent']

    if templates:
        cmd.extend(['-t', templates])
    if tags:
        cmd.extend(['-tags', tags])
    if severity:
        cmd.extend(['-severity', severity])
    if args:
        # Sanitize additional args
        safe_args = re.sub(r'[;&|`$]', '', args)
        cmd.extend(safe_args.split())

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        # Parse JSON results
        findings = []
        if os.path.exists('/tmp/results.json'):
            with open('/tmp/results.json', 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            findings.append(json.loads(line))
                        except:
                            pass
            os.remove('/tmp/results.json')

        return jsonify({
            'target': target,
            'findings': findings,
            'count': len(findings),
            'output': result.stdout,
            'error': result.stderr
        })
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'scan timeout (300s)'}), 504
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/quick', methods=['POST'])
def quick_scan():
    """Quick scan - critical/high severity only"""
    data = request.json or {}
    target = data.get('target', '')

    if not target:
        return jsonify({'error': 'target required'}), 400

    cmd = [
        'nuclei', '-u', target,
        '-severity', 'critical,high',
        '-json-export', '/tmp/results.json',
        '-silent',
        '-rate-limit', '150'
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        findings = []
        if os.path.exists('/tmp/results.json'):
            with open('/tmp/results.json', 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            findings.append(json.loads(line))
                        except:
                            pass
            os.remove('/tmp/results.json')

        return jsonify({
            'target': target,
            'severity': 'critical,high',
            'findings': findings,
            'count': len(findings)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cves', methods=['POST'])
def cve_scan():
    """Scan for known CVEs"""
    data = request.json or {}
    target = data.get('target', '')
    year = data.get('year', '')  # e.g., "2024" or "2023,2024"

    if not target:
        return jsonify({'error': 'target required'}), 400

    cmd = [
        'nuclei', '-u', target,
        '-t', 'cves/',
        '-json-export', '/tmp/results.json',
        '-silent'
    ]

    if year:
        cmd.extend(['-tags', f'cve{year}'])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        findings = []
        if os.path.exists('/tmp/results.json'):
            with open('/tmp/results.json', 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            findings.append(json.loads(line))
                        except:
                            pass
            os.remove('/tmp/results.json')

        return jsonify({
            'target': target,
            'type': 'CVE scan',
            'findings': findings,
            'count': len(findings)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/technologies', methods=['POST'])
def tech_scan():
    """Detect technologies"""
    data = request.json or {}
    target = data.get('target', '')

    if not target:
        return jsonify({'error': 'target required'}), 400

    cmd = [
        'nuclei', '-u', target,
        '-t', 'technologies/',
        '-json-export', '/tmp/results.json',
        '-silent'
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        findings = []
        if os.path.exists('/tmp/results.json'):
            with open('/tmp/results.json', 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            findings.append(json.loads(line))
                        except:
                            pass
            os.remove('/tmp/results.json')

        techs = [f.get('info', {}).get('name', f.get('template-id', 'unknown')) for f in findings]

        return jsonify({
            'target': target,
            'technologies': techs,
            'details': findings,
            'count': len(findings)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/exposures', methods=['POST'])
def exposure_scan():
    """Scan for exposed panels, configs, secrets"""
    data = request.json or {}
    target = data.get('target', '')

    if not target:
        return jsonify({'error': 'target required'}), 400

    cmd = [
        'nuclei', '-u', target,
        '-t', 'exposures/',
        '-t', 'exposed-panels/',
        '-json-export', '/tmp/results.json',
        '-silent'
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        findings = []
        if os.path.exists('/tmp/results.json'):
            with open('/tmp/results.json', 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            findings.append(json.loads(line))
                        except:
                            pass
            os.remove('/tmp/results.json')

        return jsonify({
            'target': target,
            'type': 'exposures',
            'findings': findings,
            'count': len(findings)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/misconfigs', methods=['POST'])
def misconfig_scan():
    """Scan for misconfigurations"""
    data = request.json or {}
    target = data.get('target', '')

    if not target:
        return jsonify({'error': 'target required'}), 400

    cmd = [
        'nuclei', '-u', target,
        '-t', 'misconfiguration/',
        '-t', 'miscellaneous/',
        '-json-export', '/tmp/results.json',
        '-silent'
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        findings = []
        if os.path.exists('/tmp/results.json'):
            with open('/tmp/results.json', 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            findings.append(json.loads(line))
                        except:
                            pass
            os.remove('/tmp/results.json')

        return jsonify({
            'target': target,
            'type': 'misconfigurations',
            'findings': findings,
            'count': len(findings)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/templates', methods=['GET'])
def list_templates():
    """List available template categories"""
    try:
        categories = []
        if os.path.exists(TEMPLATES_PATH):
            for item in os.listdir(TEMPLATES_PATH):
                path = os.path.join(TEMPLATES_PATH, item)
                if os.path.isdir(path) and not item.startswith('.'):
                    count = sum(1 for f in os.listdir(path) if f.endswith('.yaml'))
                    categories.append({'name': item, 'count': count})

        return jsonify({
            'path': TEMPLATES_PATH,
            'categories': sorted(categories, key=lambda x: x['count'], reverse=True)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/version', methods=['GET'])
def version():
    result = subprocess.run(['nuclei', '-version'], capture_output=True, text=True)
    return jsonify({'version': result.stdout.strip() or result.stderr.strip()})

@app.route('/health', methods=['GET'])
def health():
    return 'ok'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
