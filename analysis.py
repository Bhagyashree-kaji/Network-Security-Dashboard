import logging
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import Counter
from sqlalchemy import func, desc

logger = logging.getLogger(__name__)

# Anomaly detection thresholds
PORT_SCAN_THRESHOLD = 15  # Number of different ports in short time
SYN_FLOOD_THRESHOLD = 20  # Number of SYN packets from same source
TRAFFIC_SPIKE_FACTOR = 3.0  # Current traffic vs average baseline

def get_traffic_summary():
    """Get summary of recent network traffic"""
    from models import Packet, db
    from app import app
    
    with app.app_context():
        # Get total packets in last hour
        hour_ago = datetime.utcnow() - timedelta(hours=1)
        total_packets = Packet.query.filter(Packet.timestamp >= hour_ago).count()
        
        # Get total data transferred
        total_bytes = db.session.query(func.sum(Packet.length)).filter(
            Packet.timestamp >= hour_ago
        ).scalar() or 0
        
        # Convert to MB
        total_mb = total_bytes / (1024 * 1024)
        
        # Get packet rate per minute
        packets_per_minute = total_packets / 60
        
        # Get protocol distribution
        protocol_counts = db.session.query(
            Packet.protocol, func.count(Packet.id)
        ).filter(
            Packet.timestamp >= hour_ago
        ).group_by(Packet.protocol).all()
        
        protocols = {proto: count for proto, count in protocol_counts}
        
        return {
            'total_packets': total_packets,
            'total_mb': round(total_mb, 2),
            'packets_per_minute': round(packets_per_minute, 2),
            'protocols': protocols
        }

def get_top_protocols():
    """Get the most common protocols in recent traffic"""
    from models import Packet, db
    from app import app
    
    with app.app_context():
        # Get protocol counts from the last hour
        hour_ago = datetime.utcnow() - timedelta(hours=1)
        
        protocol_data = db.session.query(
            Packet.protocol, 
            func.count(Packet.id).label('packet_count'),
            func.sum(Packet.length).label('bytes')
        ).filter(
            Packet.timestamp >= hour_ago
        ).group_by(Packet.protocol).order_by(desc('bytes')).limit(10).all()
        
        result = []
        for protocol, packet_count, bytes_count in protocol_data:
            result.append({
                'protocol': protocol,
                'packet_count': packet_count,
                'bytes': bytes_count,
                'mb': round(bytes_count / (1024 * 1024), 2)
            })
        
        return result

def get_top_ips():
    """Get the most active IP addresses in recent traffic"""
    from models import Packet, db
    from app import app
    
    with app.app_context():
        # Get data from the last hour
        hour_ago = datetime.utcnow() - timedelta(hours=1)
        
        # Top source IPs
        source_ips = db.session.query(
            Packet.source_ip,
            func.count(Packet.id).label('packet_count'),
            func.sum(Packet.length).label('bytes')
        ).filter(
            Packet.timestamp >= hour_ago
        ).group_by(Packet.source_ip).order_by(desc('bytes')).limit(10).all()
        
        # Top destination IPs
        dest_ips = db.session.query(
            Packet.destination_ip,
            func.count(Packet.id).label('packet_count'),
            func.sum(Packet.length).label('bytes')
        ).filter(
            Packet.timestamp >= hour_ago
        ).group_by(Packet.destination_ip).order_by(desc('bytes')).limit(10).all()
        
        source_result = []
        for ip, packet_count, bytes_count in source_ips:
            source_result.append({
                'ip': ip,
                'packet_count': packet_count,
                'bytes': bytes_count,
                'mb': round(bytes_count / (1024 * 1024), 2)
            })
        
        dest_result = []
        for ip, packet_count, bytes_count in dest_ips:
            dest_result.append({
                'ip': ip,
                'packet_count': packet_count,
                'bytes': bytes_count,
                'mb': round(bytes_count / (1024 * 1024), 2)
            })
        
        return {
            'source': source_result,
            'destination': dest_result
        }

def detect_anomalies(app):
    """Detect anomalies in network traffic"""
    with app.app_context():
        from models import Packet, Alert, db
        
        # Get recent packets for analysis (last 5 minutes)
        five_min_ago = datetime.utcnow() - timedelta(minutes=5)
        recent_packets = Packet.query.filter(Packet.timestamp >= five_min_ago).all()
        
        if not recent_packets:
            return
        
        alerts = []
        
        # Detect potential port scans (one source IP connecting to many destination ports)
        source_ips = {}
        for packet in recent_packets:
            if packet.source_ip and packet.destination_port:
                if packet.source_ip not in source_ips:
                    source_ips[packet.source_ip] = set()
                source_ips[packet.source_ip].add(packet.destination_port)
        
        for source_ip, ports in source_ips.items():
            if len(ports) >= PORT_SCAN_THRESHOLD:
                # Check if we already have a similar alert in the last hour
                hour_ago = datetime.utcnow() - timedelta(hours=1)
                existing_alert = Alert.query.filter(
                    Alert.alert_type == 'PORT_SCAN',
                    Alert.source_ip == source_ip,
                    Alert.timestamp >= hour_ago
                ).first()
                
                if not existing_alert:
                    alert = Alert(
                        alert_type='PORT_SCAN',
                        severity='high',
                        source_ip=source_ip,
                        message=f"Possible port scan detected from {source_ip} ({len(ports)} ports in 5 min)",
                        details=f"Ports accessed: {', '.join(str(p) for p in sorted(ports)[:20])}..."
                    )
                    alerts.append(alert)
        
        # Detect potential SYN flood attacks
        syn_counts = Counter()
        for packet in recent_packets:
            if packet.protocol == 'TCP' and 'SYN' in (packet.info or ''):
                syn_counts[packet.source_ip] += 1
        
        for source_ip, count in syn_counts.items():
            if count >= SYN_FLOOD_THRESHOLD:
                # Check if we already have a similar alert in the last hour
                hour_ago = datetime.utcnow() - timedelta(hours=1)
                existing_alert = Alert.query.filter(
                    Alert.alert_type == 'SYN_FLOOD',
                    Alert.source_ip == source_ip,
                    Alert.timestamp >= hour_ago
                ).first()
                
                if not existing_alert:
                    alert = Alert(
                        alert_type='SYN_FLOOD',
                        severity='critical',
                        source_ip=source_ip,
                        message=f"Possible SYN flood attack from {source_ip} ({count} SYN packets in 5 min)",
                        details=f"High volume of TCP SYN packets may indicate a denial of service attempt"
                    )
                    alerts.append(alert)
        
        # Detect unusual traffic volume (compare to previous period)
        ten_min_ago = datetime.utcnow() - timedelta(minutes=10)
        previous_packets = Packet.query.filter(
            Packet.timestamp >= ten_min_ago,
            Packet.timestamp < five_min_ago
        ).all()
        
        if previous_packets:
            current_volume = sum(p.length for p in recent_packets if p.length)
            previous_volume = sum(p.length for p in previous_packets if p.length)
            
            # Avoid division by zero
            if previous_volume > 0:
                ratio = current_volume / previous_volume
                
                if ratio >= TRAFFIC_SPIKE_FACTOR:
                    # Check if we already have a similar alert in the last hour
                    hour_ago = datetime.utcnow() - timedelta(hours=1)
                    existing_alert = Alert.query.filter(
                        Alert.alert_type == 'TRAFFIC_SPIKE',
                        Alert.timestamp >= hour_ago
                    ).first()
                    
                    if not existing_alert:
                        alert = Alert(
                            alert_type='TRAFFIC_SPIKE',
                            severity='medium',
                            message=f"Traffic spike detected ({ratio:.1f}x normal volume)",
                            details=f"Current: {current_volume} bytes, Previous: {previous_volume} bytes"
                        )
                        alerts.append(alert)
        
        # Save alerts to database
        if alerts:
            for alert in alerts:
                db.session.add(alert)
            
            try:
                db.session.commit()
                logger.warning(f"Added {len(alerts)} new security alerts")
            except Exception as e:
                logger.error(f"Error saving alerts: {str(e)}")
                db.session.rollback()
