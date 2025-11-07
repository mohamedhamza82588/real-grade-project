#!/usr/bin/env python3
"""
NETWORK SCANNER WEB APPLICATION
Flask backend that integrates with scanner.py CLI tool
"""

from flask import Flask, render_template, jsonify, request, send_file
import subprocess
import threading
import json
import os
import glob
from datetime import datetime
import time

app = Flask(__name__)

# Global variables to track scan status
scan_status = {
    'running': False,
    'progress': 0,
    'stage': 'idle',
    'message': '',
    'report_path': None,
    'start_time': None,
    'live_output': []
}

scan_lock = threading.Lock()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/start-scan', methods=['POST'])
def start_scan():
    """Start the network security scan"""
    global scan_status

    with scan_lock:
        if scan_status['running']:
            return jsonify({
                'success': False,
                'message': 'A scan is already running'
            }), 400

        # Reset scan status
        scan_status = {
            'running': True,
            'progress': 0,
            'stage': 'initializing',
            'message': 'Initializing scan...',
            'report_path': None,
            'start_time': datetime.now().isoformat(),
            'live_output': []
        }

    # Start scan in background thread
    thread = threading.Thread(target=run_scanner)
    thread.daemon = True
    thread.start()

    return jsonify({
        'success': True,
        'message': 'Scan started successfully'
    })

def run_scanner():
    """Execute the scanner.py script and capture output"""
    global scan_status

    try:
        # Update status
        scan_status['stage'] = 'discovering'
        scan_status['message'] = 'Discovering hosts on network...'
        scan_status['progress'] = 10

        # Run the scanner using subprocess
        process = subprocess.Popen(
            ['python', 'scanner.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        # Read output line by line
        output_lines = []
        for line in process.stdout:
            line = line.strip()
            if line:
                output_lines.append(line)
                scan_status['live_output'].append(line)

                # Update progress based on output
                if '[STEP 1]' in line:
                    scan_status['stage'] = 'discovering'
                    scan_status['message'] = 'Discovering hosts...'
                    scan_status['progress'] = 25
                elif '[STEP 2]' in line:
                    scan_status['stage'] = 'scanning'
                    scan_status['message'] = 'Scanning ports...'
                    scan_status['progress'] = 50
                elif '[STEP 3]' in line:
                    scan_status['stage'] = 'analyzing'
                    scan_status['message'] = 'Analyzing vulnerabilities...'
                    scan_status['progress'] = 75
                elif '[STEP 4]' in line:
                    scan_status['stage'] = 'generating'
                    scan_status['message'] = 'Generating report...'
                    scan_status['progress'] = 90
                elif 'Report saved:' in line:
                    # Extract report path
                    report_path = line.split('Report saved:')[1].strip()
                    scan_status['report_path'] = report_path

        # Wait for process to complete
        process.wait()

        # Scan completed successfully
        scan_status['progress'] = 100
        scan_status['stage'] = 'completed'
        scan_status['message'] = 'Scan completed successfully!'

        # Find the most recent report if path not found
        if not scan_status['report_path']:
            reports = glob.glob('scan_results/*.html')
            if reports:
                scan_status['report_path'] = max(reports, key=os.path.getctime)

    except Exception as e:
        scan_status['stage'] = 'error'
        scan_status['message'] = f'Error: {str(e)}'
        scan_status['progress'] = 0
    finally:
        scan_status['running'] = False

@app.route('/scan-status')
def get_scan_status():
    """Get current scan status (for AJAX polling)"""
    return jsonify(scan_status)

@app.route('/results')
def results():
    """Display scan results"""
    # Get the most recent report
    reports = glob.glob('scan_results/*.html')
    if not reports:
        return render_template('results.html', report_found=False)

    latest_report = max(reports, key=os.path.getctime)

    # Read report content
    with open(latest_report, 'r', encoding='utf-8') as f:
        report_html = f.read()

    return render_template('results.html', 
                         report_found=True,
                         report_html=report_html,
                         report_path=latest_report)

@app.route('/download-report')
def download_report():
    """Download the latest report"""
    reports = glob.glob('scan_results/*.html')
    if not reports:
        return jsonify({'error': 'No reports found'}), 404

    latest_report = max(reports, key=os.path.getctime)
    return send_file(latest_report, as_attachment=True)

@app.route('/list-reports')
def list_reports():
    """List all available reports"""
    reports = glob.glob('scan_results/*.html')
    report_list = []

    for report in sorted(reports, key=os.path.getctime, reverse=True):
        report_list.append({
            'filename': os.path.basename(report),
            'path': report,
            'timestamp': datetime.fromtimestamp(os.path.getctime(report)).strftime('%Y-%m-%d %H:%M:%S'),
            'size': f"{os.path.getsize(report) / 1024:.2f} KB"
        })

    return jsonify(report_list)

if __name__ == '__main__':
    # Create scan_results directory if it doesn't exist
    os.makedirs('scan_results', exist_ok=True)

    # Run Flask app
    print("\n" + "="*70)
    print("NETWORK SCANNER WEB APPLICATION")
    print("="*70)
    print("Server starting on http://127.0.0.1:5000")
    print("Press CTRL+C to stop the server")
    print("="*70 + "\n")

    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)