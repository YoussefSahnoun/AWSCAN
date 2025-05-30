# backend/scans.py

from flask import Blueprint, jsonify, request, send_from_directory
from utils import list_json_results, run_scan_and_save_pdf
import os
import json

bp = Blueprint('scans', __name__)

@bp.route('/', methods=['GET'])
def list_scans():
    """
    List available raw JSON scan outputs in 'scans/'.
    Also returns status (success/failed/unknown) for each scan.
    """
    scan_files = list_json_results('scans')
    scan_list = []
    for filename in scan_files:
        status = "unknown"
        # Try to read the JSON and look for a "status" field, or infer from content
        try:
            with open(os.path.join('scans', filename), 'r', encoding='utf-8') as f:
                data = json.load(f)
                # You can adjust this logic based on your report structure
                if "status" in data:
                    status = data["status"]
                elif "failed" in filename.lower():
                    status = "failed"
                elif "success" in filename.lower():
                    status = "success"
                else:
                    # Try to infer from data (example: if there are failed checks)
                    if "summary" in data and "failed" in data["summary"]:
                        if data["summary"]["failed"] > 0:
                            status = "failed"
                        else:
                            status = "success"
        except Exception:
            # If file can't be read, keep status unknown
            pass
        scan_list.append({"filename": filename, "status": status})
    return jsonify(scan_list), 200

@bp.route('/run', methods=['POST'])
def run_scan():
    """
    Trigger a new CIS audit via:
      1) validate_creds
      2) discover_enabled_services
      3) thread_audits
      4) organize_results
      5) save both PDF and JSON
    Returns the JSON report immediately.
    """
    data = request.get_json() or {}
    ak = data.get('access_key')
    sk = data.get('secret_key')
    token = data.get('session_token')
    region = data.get('region')
    if not ak or not sk:
        return jsonify({'error': 'access_key and secret_key are required'}), 400

    try:
        # We still save both, but only return the JSON here
        _, report_json = run_scan_and_save_pdf(
            access_key=ak,
            secret_key=sk,
            session_token=token,
            region=region,
            folder='scans'
        )
        # Optionally, add a status field to the returned JSON
        if "summary" in report_json and "failed" in report_json["summary"]:
            report_json["status"] = "failed" if report_json["summary"]["failed"] > 0 else "success"
        return jsonify(report_json), 200
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'failed'}), 500

@bp.route('/results/<path:filename>', methods=['GET'])
def get_json(filename):
    """
    Retrieve a specific raw JSON report by filename.
    """
    return send_from_directory(
        'scans',
        filename,
        mimetype='application/json',
        as_attachment=False
    )
