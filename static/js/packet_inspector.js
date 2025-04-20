document.addEventListener('DOMContentLoaded', function() {
    // Current page state
    let currentPage = 0;
    let packetLimit = 50;
    let currentFilters = {
        ip: '',
        port: '',
        protocol: ''
    };
    
    // Initialize page
    loadPackets();
    
    // Set up event listeners
    document.getElementById('refresh-packets-btn').addEventListener('click', function() {
        loadPackets();
    });
    
    document.getElementById('apply-filters-btn').addEventListener('click', function() {
        applyFilters();
    });
    
    document.getElementById('clear-filters-btn').addEventListener('click', function() {
        clearFilters();
    });
    
    document.getElementById('packet-limit').addEventListener('change', function() {
        packetLimit = parseInt(this.value);
        currentPage = 0; // Reset to first page
        loadPackets();
    });
    
    document.getElementById('prev-page-btn').addEventListener('click', function() {
        if (currentPage > 0) {
            currentPage--;
            loadPackets();
        }
    });
    
    document.getElementById('next-page-btn').addEventListener('click', function() {
        currentPage++;
        loadPackets();
    });
    
    document.getElementById('packet-filter').addEventListener('keyup', function(e) {
        if (e.key === 'Enter') {
            applyFilters();
        }
    });
    
    // Functions
    function loadPackets() {
        // Show loading state
        document.getElementById('packetsBody').innerHTML = `
            <tr>
                <td colspan="7" class="text-center">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                    <p class="mt-2">Loading packets...</p>
                </td>
            </tr>
        `;
        
        // Prepare query parameters
        const params = new URLSearchParams({
            limit: packetLimit,
            offset: currentPage * packetLimit
        });
        
        // Add filters if present
        if (currentFilters.ip) params.append('ip', currentFilters.ip);
        if (currentFilters.port) params.append('port', currentFilters.port);
        if (currentFilters.protocol) params.append('protocol', currentFilters.protocol);
        
        // Fetch packets
        fetch(`/api/packets/recent?${params.toString()}`)
            .then(response => response.json())
            .then(data => {
                displayPackets(data);
                updatePagination(data.length);
            })
            .catch(error => {
                console.error('Error loading packets:', error);
                document.getElementById('packetsBody').innerHTML = `
                    <tr>
                        <td colspan="7" class="text-center text-danger">
                            <i class="fas fa-exclamation-circle me-2"></i> Error loading packets
                        </td>
                    </tr>
                `;
            });
    }
    
    function displayPackets(packets) {
        const tableBody = document.getElementById('packetsBody');
        
        if (packets.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="7" class="text-center">
                        <i class="fas fa-info-circle me-2"></i> No packets match your criteria
                    </td>
                </tr>
            `;
            return;
        }
        
        let html = '';
        
        packets.forEach(packet => {
            // Format timestamp
            const timestamp = new Date(packet.timestamp);
            const timeString = timestamp.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3});
            
            // Format source
            const source = packet.source_port ? `${packet.source_ip}:${packet.source_port}` : packet.source_ip;
            
            // Format destination
            const destination = packet.destination_port ? `${packet.destination_ip}:${packet.destination_port}` : packet.destination_ip;
            
            // Determine protocol style
            let protocolBadgeClass = 'bg-secondary';
            if (packet.protocol === 'TCP') protocolBadgeClass = 'bg-primary';
            if (packet.protocol === 'UDP') protocolBadgeClass = 'bg-success';
            if (packet.protocol === 'ICMP') protocolBadgeClass = 'bg-warning';
            if (packet.protocol === 'ARP') protocolBadgeClass = 'bg-info';
            
            html += `
                <tr>
                    <td>${timeString}</td>
                    <td>${source}</td>
                    <td>${destination}</td>
                    <td><span class="badge ${protocolBadgeClass}">${packet.protocol}</span></td>
                    <td>${packet.length} bytes</td>
                    <td>${packet.info || '-'}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary view-packet-btn" data-packet-id="${packet.id}">
                            <i class="fas fa-search"></i>
                        </button>
                    </td>
                </tr>
            `;
        });
        
        tableBody.innerHTML = html;
        
        // Add event listeners to view buttons
        document.querySelectorAll('.view-packet-btn').forEach(button => {
            button.addEventListener('click', function() {
                const packetId = this.getAttribute('data-packet-id');
                showPacketDetails(packetId, packets);
            });
        });
    }
    
    function showPacketDetails(packetId, packets) {
        // Find the packet in our current data
        const packet = packets.find(p => p.id == packetId);
        
        if (!packet) {
            console.error('Packet not found:', packetId);
            return;
        }
        
        // Format timestamp
        const timestamp = new Date(packet.timestamp);
        const timeString = timestamp.toLocaleString();
        
        // Populate basic info
        const basicInfo = document.getElementById('packet-basic-info');
        basicInfo.innerHTML = `
            <tr>
                <th scope="row">Time</th>
                <td>${timeString}</td>
            </tr>
            <tr>
                <th scope="row">Protocol</th>
                <td>${packet.protocol}</td>
            </tr>
            <tr>
                <th scope="row">Length</th>
                <td>${packet.length} bytes</td>
            </tr>
            <tr>
                <th scope="row">Source</th>
                <td>${packet.source_ip}${packet.source_port ? ':' + packet.source_port : ''}</td>
            </tr>
            <tr>
                <th scope="row">Destination</th>
                <td>${packet.destination_ip}${packet.destination_port ? ':' + packet.destination_port : ''}</td>
            </tr>
        `;
        
        // Populate header info (protocol-specific)
        const headerInfo = document.getElementById('packet-header-info');
        let headerHtml = '';
        
        if (packet.protocol === 'TCP') {
            const flags = packet.info ? packet.info.replace('Flags: ', '').split(' ') : [];
            headerHtml = `
                <tr>
                    <th scope="row">Source Port</th>
                    <td>${packet.source_port}</td>
                </tr>
                <tr>
                    <th scope="row">Destination Port</th>
                    <td>${packet.destination_port}</td>
                </tr>
                <tr>
                    <th scope="row">Flags</th>
                    <td>${flags.map(flag => `<span class="badge bg-secondary me-1">${flag}</span>`).join('')}</td>
                </tr>
            `;
        } else if (packet.protocol === 'UDP') {
            headerHtml = `
                <tr>
                    <th scope="row">Source Port</th>
                    <td>${packet.source_port}</td>
                </tr>
                <tr>
                    <th scope="row">Destination Port</th>
                    <td>${packet.destination_port}</td>
                </tr>
                <tr>
                    <th scope="row">Length</th>
                    <td>${packet.length} bytes</td>
                </tr>
            `;
        } else if (packet.protocol === 'ICMP') {
            const icmpInfo = packet.info ? packet.info.split(', ') : [''];
            const icmpType = icmpInfo[0].replace('Type: ', '');
            const icmpCode = icmpInfo[1] ? icmpInfo[1].replace('Code: ', '') : '';
            
            headerHtml = `
                <tr>
                    <th scope="row">Type</th>
                    <td>${icmpType}</td>
                </tr>
                <tr>
                    <th scope="row">Code</th>
                    <td>${icmpCode}</td>
                </tr>
            `;
        } else if (packet.protocol === 'ARP') {
            headerHtml = `
                <tr>
                    <th scope="row">Operation</th>
                    <td>${packet.info}</td>
                </tr>
                <tr>
                    <th scope="row">Sender IP</th>
                    <td>${packet.source_ip}</td>
                </tr>
                <tr>
                    <th scope="row">Target IP</th>
                    <td>${packet.destination_ip}</td>
                </tr>
            `;
        } else {
            headerHtml = `
                <tr>
                    <th scope="row">Info</th>
                    <td>${packet.info || 'No additional information'}</td>
                </tr>
            `;
        }
        
        headerInfo.innerHTML = headerHtml;
        
        // Generate a simulated hex dump
        // In a real implementation, this would come from the raw packet data
        const hexDump = document.getElementById('packet-hex-dump');
        
        // Generate a deterministic but packet-specific hex dump
        const hexBytes = [];
        const packetSeed = parseInt(packetId) % 100;
        
        // IP header (20 bytes)
        hexBytes.push('45 00'); // Version, IHL, DSCP, ECN
        hexBytes.push(packet.length.toString(16).padStart(4, '0').match(/../g).join(' ')); // Total Length
        hexBytes.push('00 00'); // Identification
        hexBytes.push('40 00'); // Flags, Fragment Offset
        hexBytes.push('40 ' + (packet.protocol === 'TCP' ? '06' : packet.protocol === 'UDP' ? '11' : '01')); // TTL, Protocol
        hexBytes.push('00 00'); // Header Checksum
        
        // Source IP
        const srcIpParts = packet.source_ip.split('.');
        hexBytes.push(parseInt(srcIpParts[0]).toString(16).padStart(2, '0') + ' ' + 
                    parseInt(srcIpParts[1]).toString(16).padStart(2, '0'));
        hexBytes.push(parseInt(srcIpParts[2]).toString(16).padStart(2, '0') + ' ' + 
                    parseInt(srcIpParts[3]).toString(16).padStart(2, '0'));
        
        // Destination IP
        const dstIpParts = packet.destination_ip.split('.');
        hexBytes.push(parseInt(dstIpParts[0]).toString(16).padStart(2, '0') + ' ' + 
                    parseInt(dstIpParts[1]).toString(16).padStart(2, '0'));
        hexBytes.push(parseInt(dstIpParts[2]).toString(16).padStart(2, '0') + ' ' + 
                    parseInt(dstIpParts[3]).toString(16).padStart(2, '0'));
        
        // TCP/UDP header
        if (packet.protocol === 'TCP' || packet.protocol === 'UDP') {
            hexBytes.push(parseInt(packet.source_port).toString(16).padStart(4, '0').match(/../g).join(' '));
            hexBytes.push(parseInt(packet.destination_port).toString(16).padStart(4, '0').match(/../g).join(' '));
        }
        
        // Add more data based on packet length
        const additionalLines = Math.max(0, Math.floor(packet.length / 16) - 3);
        for (let i = 0; i < additionalLines; i++) {
            const lineBytes = [];
            for (let j = 0; j < 8; j++) {
                const byte = ((i * 8 + j + packetSeed) % 256).toString(16).padStart(2, '0');
                lineBytes.push(byte);
            }
            hexBytes.push(lineBytes.join(' '));
        }
        
        // Format the hex dump with addresses and ASCII representation
        let hexDumpHtml = '';
        let lineCounter = 0;
        
        for (let i = 0; i < hexBytes.length; i++) {
            const byteGroup = hexBytes[i];
            
            if (i % 2 === 0) {
                hexDumpHtml += `<div>0x${(lineCounter * 16).toString(16).padStart(4, '0')}: `;
                lineCounter++;
            }
            
            hexDumpHtml += `<span class="${i < 5 ? 'text-info' : i < 9 ? 'text-warning' : 'text-light'}">${byteGroup}</span> `;
            
            if (i % 2 === 1) {
                hexDumpHtml += '</div>';
            }
        }
        
        hexDump.innerHTML = hexDumpHtml;
        
        // Show the modal
        const packetDetailModal = new bootstrap.Modal(document.getElementById('packetDetailModal'));
        packetDetailModal.show();
    }
    
    function updatePagination(itemCount) {
        const paginationInfo = document.getElementById('pagination-info');
        const prevButton = document.getElementById('prev-page-btn');
        const nextButton = document.getElementById('next-page-btn');
        
        const start = currentPage * packetLimit + 1;
        const end = currentPage * packetLimit + itemCount;
        
        // Update pagination text
        if (itemCount === 0) {
            paginationInfo.textContent = 'No packets to display';
        } else {
            paginationInfo.textContent = `Showing ${start} - ${end}`;
        }
        
        // Update button states
        prevButton.disabled = currentPage === 0;
        nextButton.disabled = itemCount < packetLimit;
    }
    
    function applyFilters() {
        // Read filter values
        currentFilters = {
            ip: document.getElementById('ip-filter').value.trim(),
            port: document.getElementById('port-filter').value.trim(),
            protocol: document.getElementById('protocol-filter').value
        };
        
        // Also check for global filter
        const globalFilter = document.getElementById('packet-filter').value.trim();
        if (globalFilter) {
            // Try to categorize the global filter
            if (globalFilter.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
                currentFilters.ip = globalFilter;
            } else if (globalFilter.match(/^\d+$/)) {
                currentFilters.port = globalFilter;
            } else if (['TCP', 'UDP', 'ICMP', 'ARP', 'IP'].includes(globalFilter.toUpperCase())) {
                currentFilters.protocol = globalFilter.toUpperCase();
            }
        }
        
        // Reset to first page and load data
        currentPage = 0;
        loadPackets();
    }
    
    function clearFilters() {
        // Clear all filter inputs
        document.getElementById('ip-filter').value = '';
        document.getElementById('port-filter').value = '';
        document.getElementById('protocol-filter').value = '';
        document.getElementById('packet-filter').value = '';
        
        // Reset filter state
        currentFilters = {
            ip: '',
            port: '',
            protocol: ''
        };
        
        // Reset to first page and load data
        currentPage = 0;
        loadPackets();
    }
});
