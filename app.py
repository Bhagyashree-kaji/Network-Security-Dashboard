import os
import logging
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager, current_user, login_required
from werkzeug.middleware.proxy_fix import ProxyFix
import threading

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Database setup
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///network_monitor.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize extensions
db.init_app(app)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Initialize database
with app.app_context():
    # Import models here to avoid circular imports
    from models import User, Packet, Alert
    db.create_all()
    logger.info("Database tables created")

# Import authentication routes
from auth import *

# Import capture module
from packet_capture import start_packet_capture

# Dashboard route
@app.route('/')
@login_required
def index():
    return render_template('dashboard.html')

# Traffic analysis route
@app.route('/traffic')
@login_required
def traffic():
    return render_template('traffic_analysis.html')

# Packet inspector route
@app.route('/packets')
@login_required
def packets():
    return render_template('packet_inspector.html')

# Alerts route
@app.route('/alerts')
@login_required
def alerts():
    return render_template('alerts.html')

# Settings route
@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

# API routes for frontend
@app.route('/api/traffic/summary')
@login_required
def traffic_summary():
    from models import Packet
    from analysis import get_traffic_summary
    summary = get_traffic_summary()
    return jsonify(summary)

@app.route('/api/traffic/top_protocols')
@login_required
def top_protocols():
    from analysis import get_top_protocols
    protocols = get_top_protocols()
    return jsonify(protocols)

@app.route('/api/traffic/top_ips')
@login_required
def top_ips():
    from analysis import get_top_ips
    ips = get_top_ips()
    return jsonify(ips)

@app.route('/api/packets/recent')
@login_required
def recent_packets():
    from models import Packet
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    
    packets = Packet.query.order_by(Packet.timestamp.desc()).limit(limit).offset(offset).all()
    return jsonify([packet.to_dict() for packet in packets])

@app.route('/api/alerts/recent')
@login_required
def recent_alerts():
    from models import Alert
    limit = request.args.get('limit', 10, type=int)
    
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(limit).all()
    return jsonify([alert.to_dict() for alert in alerts])

@app.route('/api/capture/start', methods=['POST'])
@login_required
def start_capture():
    try:
        # Start packet capture in a separate thread
        capture_thread = threading.Thread(target=start_packet_capture, args=(app,))
        capture_thread.daemon = True
        capture_thread.start()
        return jsonify({"status": "success", "message": "Packet capture started"})
    except Exception as e:
        logger.error(f"Error starting packet capture: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/capture/status')
@login_required
def capture_status():
    from packet_capture import is_capture_running
    return jsonify({"running": is_capture_running()})

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('layout.html', error="404 - Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('layout.html', error="500 - Internal server error"), 500
