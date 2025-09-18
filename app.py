import os
import json
import qrcode
import base64
import random
import secrets
import string
from urllib.parse import urlencode
from hashlib import pbkdf2_hmac
from flask import Flask, render_template, request, send_file, flash, redirect, url_for, jsonify
from cryptography.fernet import Fernet, InvalidToken

# --- APP CONFIGURATION ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key_change_this' 

# --- FOLDER AND DATABASE SETUP ---
QR_CODE_FOLDER = os.path.join(app.root_path, 'QR_code')
JSON_FOLDER = os.path.join(app.root_path, 'json_folder')
DATABASE_FILE = os.path.join(app.root_path, 'database.json')

os.makedirs(QR_CODE_FOLDER, exist_ok=True)
os.makedirs(JSON_FOLDER, exist_ok=True)

# --- STATIC KEY DERIVATION ---
USER_KEY = "3*kH&tB8zC@jV5nP"
SALT = b'some_fixed_salt_' 
kdf = pbkdf2_hmac('sha256', USER_KEY.encode('utf-8'), SALT, 100000)
key = base64.urlsafe_b64encode(kdf)
f = Fernet(key)

# --- HELPER FUNCTIONS ---
def get_all_encrypted_data():
    if not os.path.exists(DATABASE_FILE): return []
    try:
        with open(DATABASE_FILE, 'r') as file: return json.load(file)
    except (json.JSONDecodeError, FileNotFoundError): return []

def save_all_encrypted_data(data_list):
    with open(DATABASE_FILE, 'w') as file: json.dump(data_list, file, indent=4)

# --- NEW: RANDOM DATA GENERATION HELPERS (Re-added) ---
def generate_random_hex(length):
    return secrets.token_hex(length // 2)

def generate_random_int(max_digits):
    return random.randint(0, 10**max_digits - 1)

def generate_random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# --- ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

# --- NEW: ROUTE TO GENERATE RANDOM DATA (Re-added) ---
@app.route('/get-random-unique-data')
def get_random_unique_data():
    global f
    all_records = []
    all_encrypted_records = get_all_encrypted_data()
    for encrypted_record in all_encrypted_records:
        if not isinstance(encrypted_record, str): continue
        try:
            decrypted_bytes = f.decrypt(encrypted_record.encode('utf-8'))
            all_records.append(json.loads(decrypted_bytes.decode('utf-8')))
        except (InvalidToken, json.JSONDecodeError): continue
    
    while True: # Keep trying until a unique record is found
        num_relays = generate_random_int(1)
        random_data = {
            'board_id': generate_random_hex(8),
            'number_of_relays': num_relays,
            'version_number': generate_random_string(8),
            'build_number': generate_random_int(8),
            'relay_ids': sorted([generate_random_hex(16) for _ in range(num_relays)]),
            'additional_features': {
                generate_random_string(8): generate_random_string(10)
            }
        }
        if random_data not in all_records:
            return jsonify(random_data)


@app.route('/generate', methods=['POST'])
def generate_qr():
    global f
    try:
        data = {
            'board_id': request.form.get('board_id'),
            'number_of_relays': request.form.get('number_of_relays', type=int),
            'version_number': request.form.get('version_number'),
            'build_number': request.form.get('build_number', type=int), 
            'relay_ids': sorted(request.form.getlist('relay_id[]')),
            'additional_features': dict(sorted(zip(request.form.getlist('feature_key[]'), request.form.getlist('feature_value[]'))))
        }
    except (ValueError, TypeError):
        flash("Invalid number format for a field.", "error")
        return redirect(url_for('index'))

    board_id_to_check = data['board_id']
    all_encrypted_records = get_all_encrypted_data()
    for encrypted_record in all_encrypted_records:
        if not isinstance(encrypted_record, str): continue
        try:
            decrypted_bytes = f.decrypt(encrypted_record.encode('utf-8'))
            decrypted_record = json.loads(decrypted_bytes.decode('utf-8'))
            if decrypted_record.get('board_id') == board_id_to_check:
                flash(f"Board ID '{board_id_to_check}' already exists.", "error")
                return redirect(url_for('index'))
        except (InvalidToken, json.JSONDecodeError): continue 

    json_string = json.dumps(data, separators=(',', ':'))
    encrypted_data_string = f.encrypt(json_string.encode('utf-8')).decode('utf-8')

    all_encrypted_records.append(encrypted_data_string)
    save_all_encrypted_data(all_encrypted_records)
        
    qr_filename = f"{data['board_id']}.png"
    json_filepath = os.path.join(JSON_FOLDER, f"{data['board_id']}.json")
    qr_filepath = os.path.join(QR_CODE_FOLDER, qr_filename)

    with open(json_filepath, 'w') as file: file.write(encrypted_data_string)
    
    base_url = request.host_url
    decryption_url = f"{base_url}decrypt?data={encrypted_data_string}"
    
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(decryption_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(qr_filepath)

    return render_template('result.html', 
                           is_success=True,
                           board_id=data['board_id'], 
                           qr_filename=qr_filename, 
                           encrypted_data=encrypted_data_string)

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt_data():
    global f
    
    if request.method == 'GET':
        encrypted_text_from_url = request.args.get('data', '')
        return render_template('result.html', is_success=False, encrypted_data=encrypted_text_from_url)

    if request.method == 'POST':
        req_data = request.get_json()
        encrypted_text = req_data.get('encrypted_text')
        submitted_key = req_data.get('secret_key')
        
        if not encrypted_text or not submitted_key:
            return jsonify({'error': 'Missing encrypted text or secret key.'}), 400
        if submitted_key != USER_KEY:
            return jsonify({'error': 'Incorrect Secret Key.'}), 403
        try:
            decrypted_bytes = f.decrypt(encrypted_text.encode('utf-8'))
            decrypted_data = json.loads(decrypted_bytes.decode('utf-8'))
            return jsonify({'data': decrypted_data})
        except InvalidToken:
            return jsonify({'error': 'Decryption failed. The data is invalid or tampered with.'}), 400
        except Exception as e:
            return jsonify({'error': f"An unexpected error occurred: {e}"}), 500

@app.route('/qr_codes/<filename>')
def get_qr_code(filename):
    return send_file(os.path.join(QR_CODE_FOLDER, filename))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
