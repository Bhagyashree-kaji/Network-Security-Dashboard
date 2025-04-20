from app import db
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import json

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Packet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(64), index=True)
    destination_ip = db.Column(db.String(64), index=True)
    source_port = db.Column(db.Integer, nullable=True)
    destination_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(16), index=True)
    length = db.Column(db.Integer)
    info = db.Column(db.Text, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'length': self.length,
            'info': self.info
        }
    
    def __repr__(self):
        return f'<Packet {self.id}: {self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port} ({self.protocol})>'

class TrafficStat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    protocol = db.Column(db.String(16), index=True)
    bytes_count = db.Column(db.Integer, default=0)
    packets_count = db.Column(db.Integer, default=0)
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(),
            'protocol': self.protocol,
            'bytes_count': self.bytes_count,
            'packets_count': self.packets_count
        }
    
    def __repr__(self):
        return f'<TrafficStat {self.protocol}: {self.bytes_count} bytes, {self.packets_count} packets>'

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    alert_type = db.Column(db.String(32), index=True)
    severity = db.Column(db.String(16), index=True)  # 'low', 'medium', 'high', 'critical'
    source_ip = db.Column(db.String(64), nullable=True)
    destination_ip = db.Column(db.String(64), nullable=True)
    message = db.Column(db.Text)
    details = db.Column(db.Text, nullable=True)
    resolved = db.Column(db.Boolean, default=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'alert_type': self.alert_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'message': self.message,
            'details': self.details,
            'resolved': self.resolved
        }
    
    def __repr__(self):
        return f'<Alert {self.id}: {self.alert_type} - {self.severity}>'

class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<Setting {self.key}>'
