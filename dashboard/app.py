# dashboard/app.py
from flask import Flask, render_template, jsonify, request
import os
import json
from datetime import datetime

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
app = Flask(__name__)

def list_reports():
    files = []
    if os.path.isdir(REPORT_DIR):
        for fn in sorted(os.listdir(REPORT_DIR), key=lambda x: os.path.getmtime(os.path.join(REPORT_DIR, x)), reverse=True):
            if fn.endswith(".json"):
                file_path = os.path.join(REPORT_DIR, fn)
                mtime = os.path.getmtime(file_path)
                mod_time = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
                with open(file_path, 'r') as f:
                    try:
                        data = json.load(f)
                        files.append({
                            'name': fn,
                            'size': data.get('size', 0),
                            'sha256': data.get('sha256', 'N/A'),
                            'modified': mod_time,
                            'entropy': data.get('entropy', 0),
                            'suspicious': data.get('heuristics', {}).get('suspicious_strings', False)
                        })
                    except:
                        files.append({
                            'name': fn,
                            'size': 0,
                            'sha256': 'Error reading',
                            'modified': mod_time,
                            'entropy': 0,
                            'suspicious': False
                        })
    return files

@app.route("/")
def index():
    reports = list_reports()
    return render_template("index.html", reports=reports)

@app.route("/report/<name>")
def report(name):
    p = os.path.join(REPORT_DIR, name)
    if not os.path.isfile(p):
        return jsonify({"error": "not found"}), 404
    with open(p) as f:
        data = json.load(f)
    return jsonify(data)

@app.route("/api/reports")
def api_reports():
    return jsonify(list_reports())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
