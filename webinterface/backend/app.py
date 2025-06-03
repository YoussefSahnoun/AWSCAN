from flask import Flask, request, jsonify
from flask_cors import CORS
from scans import bp
app = Flask(__name__)
CORS(app) 
app.register_blueprint(bp, url_prefix='/scans')
@app.route('/api/run-audit', methods=['POST'])
def run_audit():
    data = request.json
    return jsonify({"message": "Audit completed", "data": data})

if __name__ == '__main__':
    app.run(debug=True)