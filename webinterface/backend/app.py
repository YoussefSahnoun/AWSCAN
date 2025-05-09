from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

@app.route('/api/run-audit', methods=['POST'])
def run_audit():
    # Example logic for running an audit
    data = request.json
    return jsonify({"message": "Audit completed", "data": data})

if __name__ == '__main__':
    app.run(debug=True)