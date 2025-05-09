# backend/scans.py

from flask import Blueprint, jsonify, request, send_from_directory
from utils import list_json_results, run_scan_and_save_pdf

bp = Blueprint('scans', __name__)

@bp.route('/', methods=['GET'])
def list_scans():
    """
    List available raw JSON scan outputs in 'scans/'.
    """
    return jsonify(list_json_results('scans')), 200

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
        return jsonify(report_json), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
