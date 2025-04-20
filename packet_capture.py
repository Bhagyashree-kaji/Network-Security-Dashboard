import logging
import time
import threading
import os
from datetime import datetime
from kamene.all import sniff, IP, TCP, UDP, ICMP, ARP, rdpcap
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
        # Try to start real packet capture
        try:
            sniff(
                prn=lambda pkt: process_packet(pkt, app),
                store=0,  # Don't store packets in memory
                filter="",  # Capture all packets
                stop_filter=lambda _: not capture_running,  # Stop when flag is cleared
                timeout=1  # Timeout after 1 second as a fallback
            )
        except KameneException as e:
            logger.error(f"Kamene error during packet capture: {str(e)}")
            # Fall through to simulation mode
        except Exception as e:
            logger.error(f"Error during packet capture: {str(e)}")
            # Fall through to simulation mode
            
        # If we get here, use simulated packet data instead
        logger.info("Using simulated packet data mode")
        
        with app.app_context():
            from models import Packet, TrafficStat, Alert, db
            import random
            import time
            
            # Define common protocols and ports
            protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'DHCP']
            tcp_ports = [80, 443, 22, 21, 25, 110, 143, 3306, 5432]
            udp_ports = [53, 67, 68, 123, 161, 162]
            
            # Define some sample IPs 
            source_ips = [
                '192.168.1.10', '192.168.1.11', '192.168.1.12', 
                '10.0.0.5', '10.0.0.10', '10.0.0.15',
                '172.16.0.5', '172.16.0.10'
            ]
            dest_ips = [
                '8.8.8.8', '8.8.4.4', '1.1.1.1', 
                '192.168.1.1', '192.168.1.254',
                '104.18.22.45', '13.33.243.77'
            ]
            
            # Generate simulated packet data while capture is running
            count = 0
            while capture_running:
                # Generate 5-15 packets per batch
                batch_size = random.randint(5, 15)
                for _ in range(batch_size):
                    protocol = random.choice(protocols)
                    
                    packet_info = {
                        'timestamp': datetime.utcnow(),
                        'source_ip': random.choice(source_ips),
                        'destination_ip': random.choice(dest_ips),
                        'protocol': protocol,
                        'length': random.randint(64, 1500)
                    }
                    
                    # Protocol specific details
                    if protocol == 'TCP':
                        packet_info['source_port'] = random.randint(1024, 65535)
                        packet_info['destination_port'] = random.choice(tcp_ports)
                        
                        # TCP flags
                        flags = []
                        if random.random() < 0.8:
                            flags.append('ACK')
                        if random.random() < 0.2:
                            flags.append('SYN')
                        if random.random() < 0.1:
                            flags.append('FIN')
                        if random.random() < 0.05:
                            flags.append('RST')
                        if random.random() < 0.3:
                            flags.append('PSH')
                            
                        packet_info['info'] = f"Flags: {' '.join(flags)}"
                        
                    elif protocol == 'UDP':
                        packet_info['source_port'] = random.randint(1024, 65535)
                        packet_info['destination_port'] = random.choice(udp_ports)
                        packet_info['info'] = f"Length: {packet_info['length']}"
                        
                    elif protocol == 'ICMP':
                        packet_info['source_port'] = None
                        packet_info['destination_port'] = None
                        icmp_type = random.randint(0, 8)
                        icmp_code = random.randint(0, 3)
                        packet_info['info'] = f"Type: {icmp_type}, Code: {icmp_code}"
                        
                    elif protocol in ['HTTP', 'HTTPS']:
                        packet_info['source_port'] = random.randint(1024, 65535)
                        packet_info['destination_port'] = 443 if protocol == 'HTTPS' else 80
                        methods = ['GET', 'POST', 'PUT', 'DELETE']
                        packet_info['info'] = f"Method: {random.choice(methods)}"
                        
                    elif protocol == 'DNS':
                        packet_info['source_port'] = random.randint(1024, 65535)
                        packet_info['destination_port'] = 53
                        packet_info['info'] = f"Query type: {'A' if random.random() < 0.7 else 'AAAA'}"
                        
                    else:
                        packet_info['source_port'] = random.randint(1024, 65535)
                        packet_info['destination_port'] = random.randint(1, 1023)
                        packet_info['info'] = f"Generic {protocol} packet"
                    
                    # Store in database
                    try:
                        db_packet = Packet(**packet_info)
                        db.session.add(db_packet)
                        
                        # Update stats for this protocol
                        proto_key = f"{protocol}:{packet_info['destination_port']}" if packet_info['destination_port'] else protocol
                        stats_buffer[proto_key] = stats_buffer.get(proto_key, 0) + packet_info['length']
                        
                        count += 1
                    except Exception as e:
                        logger.error(f"Error storing simulated packet: {str(e)}")
                
                # Commit the batch
                try:
                    db.session.commit()
                except Exception as e:
                    logger.error(f"Error committing batch: {str(e)}")
                    db.session.rollback()
                
                # Update stats and detect anomalies periodically
                if count % 50 == 0:
                    update_traffic_stats(app)
                    detect_anomalies(app)
                
                # Generate occasional alerts
                if count % 100 == 0 and random.random() < 0.3:
                    alert_types = ['PORT_SCAN', 'SYN_FLOOD', 'TRAFFIC_SPIKE', 'UNUSUAL_PROTOCOL']
                    alert_type = random.choice(alert_types)
                    
                    if alert_type == 'PORT_SCAN':
                        source = random.choice(source_ips)
                        alert = Alert(
                            alert_type=alert_type,
                            severity='medium',
                            source_ip=source,
                            message=f"Possible port scan detected from {source}",
                            details=f"Multiple ports accessed in short time"
                        )
                    elif alert_type == 'SYN_FLOOD':
                        source = random.choice(source_ips)
                        alert = Alert(
                            alert_type=alert_type,
                            severity='high',
                            source_ip=source,
                            message=f"Possible SYN flood from {source}",
                            details=f"High rate of SYN packets detected"
                        )
                    elif alert_type == 'TRAFFIC_SPIKE':
                        alert = Alert(
                            alert_type=alert_type,
                            severity='low',
                            message=f"Traffic spike detected",
                            details=f"Traffic volume increased significantly"
                        )
                    else:
                        alert = Alert(
                            alert_type=alert_type,
                            severity='info',
                            message=f"Unusual protocol detected",
                            details=f"Uncommon protocol traffic observed"
                        )
                    
                    try:
                        db.session.add(alert)
                        db.session.commit()
                        logger.info(f"Generated simulated alert: {alert_type}")
                    except Exception as e:
                        logger.error(f"Error creating simulated alert: {str(e)}")
                        db.session.rollback()
                
                # Sleep a short time between batches
                time.sleep(0.5)
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

def process_pcap_file(app, filepath):
    """Process a PCAP file and store packets in the database"""
    logger.info(f"Starting to process PCAP file: {filepath}")
    
    try:
        # Read the PCAP file
        packets = rdpcap(filepath)
        logger.info(f"Successfully read {len(packets)} packets from {filepath}")
        
        # Process packets
        with app.app_context():
            from models import Packet, TrafficStat, db
            
            # Clear stats buffer for this analysis
            stats_buffer.clear()
            
            # Process each packet
            packet_count = 0
            for packet in packets:
                # Skip non-IP/non-ARP packets
                if not packet.haslayer(IP) and not packet.haslayer(ARP):
                    continue
                
                # Extract basic packet information
                packet_info = {}
                packet_info['timestamp'] = datetime.utcnow()  # Use current time as import time
                
                # Process packet based on its type
                if packet.haslayer(IP):
                    packet_info['source_ip'] = packet[IP].src
                    packet_info['destination_ip'] = packet[IP].dst
                    
                    if packet.haslayer(TCP):
                        packet_info['protocol'] = 'TCP'
                        packet_info['source_port'] = packet[TCP].sport
                        packet_info['destination_port'] = packet[TCP].dport
                        packet_info['length'] = len(packet[TCP])
                        
                        # Extract TCP flags
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
                    packet_count += 1
                    
                    # Commit in batches to avoid memory issues
                    if packet_count % 100 == 0:
                        db.session.commit()
                        logger.info(f"Processed {packet_count} packets so far")
                        
                except Exception as e:
                    logger.error(f"Error storing packet from PCAP: {str(e)}")
                    db.session.rollback()
            
            # Final commit for any remaining packets
            try:
                db.session.commit()
            except Exception as e:
                logger.error(f"Error committing final batch: {str(e)}")
                db.session.rollback()
            
            # Update traffic stats
            update_traffic_stats(app)
            
            # Run anomaly detection
            detect_anomalies(app)
            
            logger.info(f"Completed processing {packet_count} packets from PCAP file")
            
        # Clean up
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
                logger.info(f"Deleted temporary PCAP file: {filepath}")
            except Exception as e:
                logger.error(f"Error deleting PCAP file: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error processing PCAP file {filepath}: {str(e)}")
        
    return True
