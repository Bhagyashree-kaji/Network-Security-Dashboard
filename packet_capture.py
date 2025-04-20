import logging
import time
import threading
from datetime import datetime
from kamene.all import sniff, IP, TCP, UDP, ICMP, ARP
from kamene.error import Kamene_Exception as KameneException
import pandas as pd
import numpy as np
from collections import defaultdict, deque

from analysis import detect_anomalies

# Global variables
capture_running = False
capture_thread = None
packet_buffer = deque(maxlen=1000)  # Store recent packets for analysis
stats_buffer = defaultdict(int)
last_analysis_time = datetime.now()
analysis_interval = 30  # seconds

logger = logging.getLogger(__name__)

def is_capture_running():
    """Check if packet capture is currently running"""
    global capture_running
    return capture_running

def process_packet(packet, app):
    """Process a captured packet and store in database"""
    with app.app_context():
        from models import Packet, TrafficStat, db
        
        # Store packet in buffer for analysis
        packet_buffer.append(packet)
        
        # Skip non-IP packets for detailed processing
        if not packet.haslayer(IP) and not packet.haslayer(ARP):
            return
        
        # Extract basic packet information
        packet_info = {}
        packet_info['timestamp'] = datetime.utcnow()
        
        # Get protocol info
        if packet.haslayer(IP):
            packet_info['source_ip'] = packet[IP].src
            packet_info['destination_ip'] = packet[IP].dst
            
            if packet.haslayer(TCP):
                packet_info['protocol'] = 'TCP'
                packet_info['source_port'] = packet[TCP].sport
                packet_info['destination_port'] = packet[TCP].dport
                packet_info['length'] = len(packet[TCP])
                flags = []
                if packet[TCP].flags.S: flags.append('SYN')
                if packet[TCP].flags.A: flags.append('ACK')
                if packet[TCP].flags.F: flags.append('FIN')
                if packet[TCP].flags.R: flags.append('RST')
                if packet[TCP].flags.P: flags.append('PSH')
                packet_info['info'] = f"Flags: {' '.join(flags)}"
                
                # Update statistics
                stats_buffer[f"TCP:{packet[TCP].dport}"] += len(packet)
                
            elif packet.haslayer(UDP):
                packet_info['protocol'] = 'UDP'
                packet_info['source_port'] = packet[UDP].sport
                packet_info['destination_port'] = packet[UDP].dport
                packet_info['length'] = len(packet[UDP])
                packet_info['info'] = f"Length: {len(packet[UDP])}"
                
                # Update statistics
                stats_buffer[f"UDP:{packet[UDP].dport}"] += len(packet)
                
            elif packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'
                packet_info['source_port'] = None
                packet_info['destination_port'] = None
                packet_info['length'] = len(packet[ICMP])
                packet_info['info'] = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"
                
                # Update statistics
                stats_buffer["ICMP"] += len(packet)
                
            else:
                packet_info['protocol'] = 'IP'
                packet_info['source_port'] = None
                packet_info['destination_port'] = None
                packet_info['length'] = len(packet)
                packet_info['info'] = f"Protocol: {packet[IP].proto}"
                
                # Update statistics
                stats_buffer["IP"] += len(packet)
                
        elif packet.haslayer(ARP):
            packet_info['protocol'] = 'ARP'
            packet_info['source_ip'] = packet[ARP].psrc
            packet_info['destination_ip'] = packet[ARP].pdst
            packet_info['source_port'] = None
            packet_info['destination_port'] = None
            packet_info['length'] = len(packet)
            
            if packet[ARP].op == 1:
                packet_info['info'] = "ARP Request"
            else:
                packet_info['info'] = "ARP Reply"
                
            # Update statistics
            stats_buffer["ARP"] += len(packet)
        
        # Store packet in database
        try:
            db_packet = Packet(**packet_info)
            db.session.add(db_packet)
            db.session.commit()
        except Exception as e:
            logger.error(f"Error storing packet: {str(e)}")
            db.session.rollback()
        
        # Update traffic statistics periodically
        global last_analysis_time
        now = datetime.now()
        if (now - last_analysis_time).total_seconds() >= analysis_interval:
            update_traffic_stats(app)
            detect_anomalies(app)
            last_analysis_time = now

def update_traffic_stats(app):
    """Update traffic statistics in the database"""
    with app.app_context():
        from models import TrafficStat, db
        
        # Get current timestamp
        now = datetime.utcnow()
        
        # Process stats_buffer and store in database
        for protocol, bytes_count in stats_buffer.items():
            try:
                # Parse protocol info
                if ':' in protocol:
                    proto_name, port = protocol.split(':')
                    stat = TrafficStat(
                        timestamp=now,
                        protocol=f"{proto_name} (Port {port})",
                        bytes_count=bytes_count,
                        packets_count=1  # Simplified, could be more accurate
                    )
                else:
                    stat = TrafficStat(
                        timestamp=now,
                        protocol=protocol,
                        bytes_count=bytes_count,
                        packets_count=1  # Simplified, could be more accurate
                    )
                
                db.session.add(stat)
            except Exception as e:
                logger.error(f"Error updating traffic stats: {str(e)}")
        
        try:
            db.session.commit()
            # Clear the stats buffer after committing
            stats_buffer.clear()
        except Exception as e:
            logger.error(f"Error committing traffic stats: {str(e)}")
            db.session.rollback()

def packet_sniffer(app):
    """Main packet sniffing function"""
    global capture_running
    
    logger.info("Starting packet capture")
    capture_running = True
    
    try:
        # Start packet capture
        sniff(
            prn=lambda pkt: process_packet(pkt, app),
            store=0,  # Don't store packets in memory
            filter="",  # Capture all packets
            stop_filter=lambda _: not capture_running  # Stop when flag is cleared
        )
    except KameneException as e:
        logger.error(f"Kamene error during packet capture: {str(e)}")
    except Exception as e:
        logger.error(f"Error during packet capture: {str(e)}")
    finally:
        logger.info("Packet capture stopped")
        capture_running = False

def start_packet_capture(app):
    """Start packet capture in a separate thread"""
    global capture_thread, capture_running
    
    if capture_running:
        logger.warning("Packet capture already running")
        return False
    
    capture_thread = threading.Thread(target=packet_sniffer, args=(app,))
    capture_thread.daemon = True
    capture_thread.start()
    
    return True

def stop_packet_capture():
    """Stop ongoing packet capture"""
    global capture_running
    
    if not capture_running:
        logger.warning("No packet capture running")
        return False
    
    logger.info("Stopping packet capture")
    capture_running = False
    
    # Wait for thread to finish
    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=2.0)
    
    return True
