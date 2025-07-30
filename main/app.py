from flask import Flask, request, jsonify, render_template
from main.encrypt import pseudonymize_json
from main.decrypt import decrypt_json_data
import json
import os
import requests

app = Flask(__name__)

# Make sure this is a 32-byte base64 encoded key (generate using Fernet.generate_key())
ENCRYPTION_KEY = b''  # replace with your key inside ''
SAVED_FILE = 'pseudonymized_data.json'
OPA_URL = "http://localhost:8181/v1/data/api/authz/allow"

def check_access(client_ip):
    opa_input = {"input": {"client_ip": client_ip}}
    response = requests.post(OPA_URL, json=opa_input)
    print("OPA input sent:", opa_input)
    print("OPA response:", response.json())
    return response.json().get("result", False)


@app.before_request
def opa_authorization():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    print("Client IP:", client_ip)  # Debug log

    if not check_access(client_ip):
        return jsonify({"error": "Access Denied"}), 403

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/pseudonymize', methods=['POST'])
def pseudonymize():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if file and file.filename.endswith('.json'):
        try:
            json_data = json.load(file)
            pseudonymized_data = pseudonymize_json(json_data, ENCRYPTION_KEY)
            with open(SAVED_FILE, 'w') as f:
                json.dump(pseudonymized_data, f)
            return jsonify(pseudonymized_data)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    else:
        return jsonify({"error": "Invalid file type. Please upload a .json file."}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if not os.path.exists(SAVED_FILE):
        return jsonify({"error": "No encrypted file found. Please encrypt a file first."}), 400
    try:
        with open(SAVED_FILE, 'r') as f:
            pseudonymized_data = json.load(f)
        decrypted_data = decrypt_json_data(pseudonymized_data, ENCRYPTION_KEY)
        return jsonify(decrypted_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
