from flask import Flask, request, jsonify
import subprocess
import re

app = Flask(__name__)

def extract_vulnerabilities(nikto_output):
    vulnerabilities = []
    current_vuln = {}

    lines = nikto_output.split('\n')

    for line in lines:
        if line.startswith("+") or line.startswith("-") or line.startswith("*"):
            if current_vuln:
                vulnerabilities.append(current_vuln)
            current_vuln = {'id': len(vulnerabilities) + 1}
            current_vuln['title'] = line.strip().lstrip("+-*").strip()
        elif line.startswith("Severity"):
            current_vuln['severity'] = line.split(":")[1].strip()

    if current_vuln:
        vulnerabilities.append(current_vuln)

    return vulnerabilities

@app.route('/analyze-url', methods=['GET'])
def analyze_url():
    url = request.args.get('url')

    if not url:
        return jsonify({'error': 'Parámetro "url" no proporcionado'}), 400

    try:
  
        cmd = f'nikto -h {url}'
        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
        vulnerabilities = extract_vulnerabilities(output)
        report = {
            'url': url,
            'vulnerabilities': vulnerabilities
        }

        return jsonify(report), 200

    except subprocess.CalledProcessError as e:
        return jsonify({'error': f'Error al ejecutar Nikto: {e.output}'}), 500

if __name__ == '__main__':
    app.run(debug=True, port=8080)