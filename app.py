from flask import Flask, render_template, request, jsonify, redirect, url_for
import os
import subprocess
import sys
import threading
import queue
import requests
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode='threading')

SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), 'scripts')

import json

CUSTOMERS_FILE = os.path.join(os.path.dirname(__file__), 'customers.json')

def load_customers():
    if os.path.exists(CUSTOMERS_FILE):
        with open(CUSTOMERS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_customers(customers):
    with open(CUSTOMERS_FILE, 'w') as f:
        json.dump(customers, f, indent=4)

@app.route('/')
def index():
    scripts = []
    if os.path.exists(SCRIPTS_DIR):
        for f in os.listdir(SCRIPTS_DIR):
            if f.endswith('.py'):
                scripts.append(f)
    
    customers = load_customers()
    return render_template('index.html', scripts=scripts, customers=customers)

@app.route('/config')
def config():
    customers = load_customers()
    return render_template('config.html', customers=customers)

@app.route('/execute_page')
def execute_page():
    script_name = request.args.get('script')
    customer_name = request.args.get('customer', '')
    
    if not script_name:
        return redirect(url_for('index'))
        
    customers = load_customers()
    customer = next((c for c in customers if c['customer_name'] == customer_name), {})
    
    # Load script metadata
    metadata = load_scripts_metadata()
    script_meta = metadata.get(script_name, {})
    requires_token = script_meta.get('requires_token', False)
    requires_input = script_meta.get('requires_input', False)
    
    return render_template('execute.html', 
                         script_name=script_name, 
                         customer=customer, 
                         customers=customers,
                         selected_customer=customer_name,
                         requires_token=requires_token,
                         requires_input=requires_input,
                         args={})

@app.route('/api/customers', methods=['POST'])
def save_customer_data():
    data = request.json
    customers = load_customers()
    
    # Check if it's an update or new
    updated = False
    for i, c in enumerate(customers):
        if c['customer_name'] == data['customer_name']:
            customers[i] = data
            updated = True
            break
    
    if not updated:
        customers.append(data)
        
    save_customers(customers)
    return jsonify({'status': 'success'})

@app.route('/api/customers/<path:customer_name>', methods=['DELETE'])
def delete_customer(customer_name):
    customers = load_customers()
    customers = [c for c in customers if c['customer_name'] != customer_name]
    save_customers(customers)
    return jsonify({'status': 'success'})

@app.route('/api/token/generate', methods=['POST'])
def generate_token():
    """Generate a new authentication token for a customer using AWS Cognito"""
    import requests
    
    data = request.json
    customer_name = data.get('customer_name', '')
    
    if not customer_name:
        return jsonify({'error': 'Customer name required'}), 400
    
    # Load customer data
    customers = load_customers()
    customer = next((c for c in customers if c['customer_name'] == customer_name), None)
    
    if not customer:
        return jsonify({'error': f'Customer {customer_name} not found'}), 404
    
    # Get required fields
    username = customer.get('username', '')
    password = customer.get('password', '')
    client_id = customer.get('catalogueClientID', '')
    auth_region = customer.get('aws-region', 'us-east-1')
    
    if not username or not password:
        return jsonify({'error': 'Customer credentials (username/password) not configured'}), 400
    
    if not client_id:
        return jsonify({'error': 'Customer client ID not configured'}), 400
    
    try:
        # Prepare AWS Cognito request
        payload = {
            "AuthParameters": {
                "USERNAME": username,
                "PASSWORD": password
            },
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": client_id
        }
        
        headers = {
            "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
            "Content-Type": "application/x-amz-json-1.1"
        }
        
        # Call AWS Cognito
        cognito_url = f"https://cognito-idp.{auth_region}.amazonaws.com/"
        response = requests.post(cognito_url, json=payload, headers=headers)
        response.raise_for_status()
        
        # Extract token from response
        auth_result = response.json().get("AuthenticationResult")
        if not auth_result:
            return jsonify({'error': 'Authentication failed - no result returned'}), 401
        
        token = auth_result.get("AccessToken")
        if not token:
            return jsonify({'error': 'Authentication failed - no access token returned'}), 401
        
        expires_in = auth_result.get("ExpiresIn", 3600)  # Default to 1 hour
        
        return jsonify({
            'status': 'success',
            'token': token,
            'expires_in': expires_in
        })
        
    except requests.exceptions.HTTPError as e:
        error_msg = f'AWS Cognito authentication failed: {str(e)}'
        if e.response is not None:
            try:
                error_detail = e.response.json()
                error_msg = f'AWS Cognito error: {error_detail.get("__type", "Unknown")} - {error_detail.get("message", str(e))}'
            except:
                pass
        return jsonify({'error': error_msg}), 401
    except Exception as e:
        return jsonify({'error': f'Token generation failed: {str(e)}'}), 500


# --- Script Management ---

SCRIPTS_METADATA_FILE = os.path.join(os.path.dirname(__file__), 'scripts_metadata.json')

def load_scripts_metadata():
    if os.path.exists(SCRIPTS_METADATA_FILE):
        with open(SCRIPTS_METADATA_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_scripts_metadata(metadata):
    with open(SCRIPTS_METADATA_FILE, 'w') as f:
        json.dump(metadata, f, indent=4)

@app.route('/manage_scripts')
def manage_scripts():
    scripts = []
    metadata = load_scripts_metadata()
    
    if os.path.exists(SCRIPTS_DIR):
        for f in os.listdir(SCRIPTS_DIR):
            if f.endswith('.py'):
                script_meta = metadata.get(f, {})
                scripts.append({
                    'name': f,
                    'requires_input': script_meta.get('requires_input', False),
                    'requires_token': script_meta.get('requires_token', False)
                })
    
    edit_script = request.args.get('edit')
    edit_mode = False
    script_data = {}
    
    if edit_script:
        edit_mode = True
        script_meta = metadata.get(edit_script, {})
        script_data = {
            'name': edit_script,
            'requires_input': script_meta.get('requires_input', False),
            'requires_token': script_meta.get('requires_token', False)
        }
    
    return render_template('manage_scripts.html', 
                         scripts=scripts, 
                         edit_mode=edit_mode, 
                         script_data=script_data)

@app.route('/api/scripts', methods=['POST'])
def upload_script():
    try:
        script_name = request.form.get('script_name')
        requires_input = request.form.get('requires_input') == 'true'
        requires_token = request.form.get('requires_token') == 'true'
        script_file = request.files.get('script_file')
        
        if not script_name or not script_name.endswith('.py'):
            return jsonify({'error': 'Invalid script name. Must end with .py'}), 400
        
        if not script_file:
            return jsonify({'error': 'No file provided'}), 400
        
        # Ensure scripts directory exists
        if not os.path.exists(SCRIPTS_DIR):
            os.makedirs(SCRIPTS_DIR)
        
        # Save the file
        script_path = os.path.join(SCRIPTS_DIR, script_name)
        script_file.save(script_path)
        
        # Save metadata
        metadata = load_scripts_metadata()
        metadata[script_name] = {
            'requires_input': requires_input,
            'requires_token': requires_token
        }
        save_scripts_metadata(metadata)
        
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scripts/<path:script_name>', methods=['PUT'])
def update_script(script_name):
    try:
        requires_input = request.form.get('requires_input') == 'true'
        requires_token = request.form.get('requires_token') == 'true'
        script_file = request.files.get('script_file')
        
        script_path = os.path.join(SCRIPTS_DIR, script_name)
        
        # Update file if provided
        if script_file:
            script_file.save(script_path)
        
        # Update metadata
        metadata = load_scripts_metadata()
        metadata[script_name] = {
            'requires_input': requires_input,
            'requires_token': requires_token
        }
        save_scripts_metadata(metadata)
        
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scripts/<path:script_name>', methods=['DELETE'])
def delete_script(script_name):
    try:
        script_path = os.path.join(SCRIPTS_DIR, script_name)
        
        # Delete file
        if os.path.exists(script_path):
            os.remove(script_path)
        
        # Delete metadata
        metadata = load_scripts_metadata()
        if script_name in metadata:
            del metadata[script_name]
            save_scripts_metadata(metadata)
        
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --- SocketIO Logic ---

process_map = {}

def read_output(process, sid):
    """Reads stdout from the process and emits it to the client."""
    while True:
        # Read up to 1024 bytes. Since bufsize=0, this returns whatever is available
        # immediately, or blocks until at least 1 byte is available.
        output = process.stdout.read(1024)
        
        if output == b'' and process.poll() is not None:
            break
            
        if output:
            try:
                # Decode bytes to string
                text = output.decode('utf-8', errors='replace')
                socketio.emit('output', {'data': text}, room=sid)
            except Exception:
                pass
                
    process.stdout.close()
    process.wait()
    socketio.emit('script_done', {'returncode': process.returncode}, room=sid)
    if sid in process_map:
        del process_map[sid]

@socketio.on('start_script')
def handle_start_script(data):
    print(f"Starting script for session {request.sid}")
    script_name = data.get('script')
    args = data.get('args', {})
    sid = request.sid

    script_path = os.path.join(SCRIPTS_DIR, script_name)
    if not os.path.exists(script_path):
        emit('output', {'data': f'Error: Script {script_name} not found.\n'})
        return

    cmd = [sys.executable, "-u", script_path] # -u for unbuffered output
    
    # Customer and token args removed as per user request
    
    if isinstance(args, list):
        cmd.extend(args)
    elif isinstance(args, dict):
        for key, value in args.items():
            cmd.extend([f'--{key}', str(value)])

    try:
        # Popen with pipes for stdin/stdout
        # Use binary mode and unbuffered I/O to capture prompts immediately
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, # Merge stderr into stdout
            stdin=subprocess.PIPE,
            text=False, # Binary mode
            bufsize=0   # Unbuffered
        )
        
        process_map[sid] = process
        
        # Start background thread to read output
        socketio.start_background_task(target=read_output, process=process, sid=sid)
        
    except Exception as e:
        emit('output', {'data': f'Error starting script: {str(e)}\n'})

@socketio.on('input')
def handle_input(data):
    sid = request.sid
    user_input = data.get('data')
    
    if sid in process_map:
        process = process_map[sid]
        if process.poll() is None: # Check if running
            try:
                # Encode input to bytes
                process.stdin.write(user_input.encode('utf-8'))
                process.stdin.flush()
            except Exception as e:
                emit('output', {'data': f'Error writing input: {str(e)}\n'})

@socketio.on('kill_script')
def handle_kill_script():
    print(f"Killing script for session {request.sid}")
    sid = request.sid
    if sid in process_map:
        process = process_map[sid]
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
        del process_map[sid]
        emit('output', {'data': '\nProcess terminated by user.\n'})

if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
