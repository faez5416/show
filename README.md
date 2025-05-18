Fuck Society Camera Capture Tool
A Flask-based web app to capture webcam snapshots. Created by Faez.
Requirements

Python 3.6+
OpenSSL (for HTTPS, required for camera access over network)
A webcam
Supported OS: Linux, Windows, macOS

Setup

Install Dependencies:

Install Python and pip.
Linux:sudo apt update
sudo apt install python3 python3-pip openssl


Windows: Download Python from python.org.
macOS:brew install python openssl


Install Python packages:pip install -r requirements.txt




Optional: Configure:

Edit ~/fuck_society_config.json to set custom paths, password, or port:{
    "image_folder": "~/fuck_society_images",
    "admin_password": "faez123",
    "port": 5000,
    "jpeg_quality": 85
}




Run the App:
python3 camera_capture_tool.py --port 5000


Use --no-ssl for testing (camera only works on localhost):python3 camera_capture_tool.py --no-ssl


Creates ~/fuck_society_images and ~/fuck_society_logs.


Access the App:

Browser:
http://localhost:5000 (local, with --no-ssl).
https://localhost:5000 or https://<your-ip>:5000 (accept cert warning).


Find your IP:ip addr show | grep inet  # Linux
ipconfig  # Windows
ifconfig | grep inet  # macOS


Allow camera access.
Click "Take Snapshot" to save images.


Admin Access:

Go to /admin, enter password (default: faez123, change in config).
View images in ~/fuck_society_images.
Click "Logout" to end session.



Troubleshooting

Camera not working:
Use localhost or HTTPS.
Check browser camera permissions.


SSL errors:
Install OpenSSL or use --no-ssl.


Permission errors:mkdir -p ~/fuck_society_images ~/fuck_society_logs
chmod 755 ~/fuck_society_images ~/fuck_society_logs


Check logs:cat ~/fuck_society_logs/app.log



Notes

Update /terms for legal compliance (e.g., GDPR).
For network access, open port 5000:sudo ufw allow 5000  # Linux



