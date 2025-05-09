from flask import Blueprint, jsonify, request, send_from_directory
from utils import list_reports, run_scan_and_save_pdf

bp = Blueprint('scans', __name__)

@bp.route('/', methods=['GET'])
def list_scans():
    """
    List available PDF scan reports in the 'scans/' folder.
    """
    reports = list_reports('scans')
    return jsonify(reports), 200

@bp.route('/run', methods=['POST'])
def run_scan():
    """
    Trigger a new CIS benchmark scan and save the results as a PDF.
    Expects JSON: { access_key: str, secret_key: str }
    """
    data = request.get_json()
    access_key = data.get('access_key')
    secret_key = data.get('secret_key')

    filename = run_scan_and_save_pdf(access_key, secret_key, 'scans')
    return jsonify({'pdf': filename}), 200

@bp.route('/reports/<path:filename>', methods=['GET'])
def get_report(filename):
    """
    Download a specific PDF report by filename.
    """
    return send_from_directory('scans', filename, as_attachment=True)