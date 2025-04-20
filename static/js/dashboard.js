document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    const protocolChartCtx = document.getElementById('protocolChart').getContext('2d');
    const trafficChartCtx = document.getElementById('trafficChart').getContext('2d');
    
    let protocolChart = null;
    let trafficChart = null;
    
    // Initialize dashboard
    updateCaptureStatus();
    loadDashboardData();
    loadRecentAlerts();
    loadTopIPs();
    
    // Set up refresh button
    document.getElementById('refresh-data-btn').addEventListener('click', function() {
        loadDashboardData();
        loadRecentAlerts();
        loadTopIPs();
    });
    
    // Set up start capture button
    document.getElementById('start-capture-btn').addEventListener('click', function() {
        startCapture();
    });
    
    // Periodically update data (every 30 seconds)
    setInterval(function() {
        updateCaptureStatus();
        loadDashboardData();
        loadRecentAlerts();
    }, 30000);
    
    // Functions
    function updateCaptureStatus() {
        fetch('/api/capture/status')
            .then(response => response.json())
            .then(data => {
                const statusIndicator = document.getElementById('capture-status-indicator');
                const statusText = document.getElementById('capture-status-text');
                
                if (data.running) {
                    statusIndicator.innerHTML = '<span class="badge bg-success"><i class="fas fa-check-circle me-1"></i> Active</span>';
                    statusText.textContent = 'Packet capture is running. Network traffic is being monitored.';
                    document.getElementById('start-capture-btn').disabled = true;
                    document.getElementById('start-capture-btn').innerHTML = '<i class="fas fa-check me-1"></i> Capture Running';
                } else {
                    statusIndicator.innerHTML = '<span class="badge bg-danger"><i class="fas fa-times-circle me-1"></i> Inactive</span>';
                    statusText.textContent = 'Packet capture is not active. Click "Start Capture" to begin monitoring.';
                    document.getElementById('start-capture-btn').disabled = false;
                    document.getElementById('start-capture-btn').innerHTML = '<i class="fas fa-play me-1"></i> Start Capture';
                }
            })
            .catch(error => {
                console.error('Error checking capture status:', error);
                const statusIndicator = document.getElementById('capture-status-indicator');
                statusIndicator.innerHTML = '<span class="badge bg-warning"><i class="fas fa-exclamation-circle me-1"></i> Unknown</span>';
            });
    }
    
    function startCapture() {
        const startBtn = document.getElementById('start-capture-btn');
        startBtn.disabled = true;
        startBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i> Starting...';
        
        fetch('/api/capture/start', {
            method: 'POST',
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                updateCaptureStatus();
                startBtn.innerHTML = '<i class="fas fa-check me-1"></i> Capture Started';
                setTimeout(() => {
                    startBtn.innerHTML = '<i class="fas fa-play me-1"></i> Start Capture';
                    startBtn.disabled = false;
                }, 2000);
            } else {
                startBtn.innerHTML = '<i class="fas fa-exclamation-triangle me-1"></i> Error';
                startBtn.disabled = false;
                alert('Error starting capture: ' + data.message);
                setTimeout(() => {
                    startBtn.innerHTML = '<i class="fas fa-play me-1"></i> Start Capture';
                }, 2000);
            }
        })
        .catch(error => {
            console.error('Error starting capture:', error);
            startBtn.innerHTML = '<i class="fas fa-exclamation-triangle me-1"></i> Error';
            startBtn.disabled = false;
            setTimeout(() => {
                startBtn.innerHTML = '<i class="fas fa-play me-1"></i> Start Capture';
            }, 2000);
        });
    }
    
    function loadDashboardData() {
        // Fetch traffic summary
        fetch('/api/traffic/summary')
            .then(response => response.json())
            .then(data => {
                // Update summary cards
                document.getElementById('total-packets').textContent = data.total_packets.toLocaleString();
                document.getElementById('total-mb').textContent = data.total_mb.toLocaleString() + ' MB';
                document.getElementById('packet-rate').textContent = data.packets_per_minute.toLocaleString() + ' pkt/min';
                
                // Protocol distribution chart
                updateProtocolChart(data.protocols);
            })
            .catch(error => {
                console.error('Error loading traffic summary:', error);
            });
            
        // Fetch recent alerts count
        fetch('/api/alerts/recent')
            .then(response => response.json())
            .then(data => {
                document.getElementById('active-alerts').textContent = data.length;
            })
            .catch(error => {
                console.error('Error loading alert count:', error);
            });
    }
    
    function updateProtocolChart(protocols) {
        const protocolData = {
            labels: Object.keys(protocols),
            datasets: [{
                data: Object.values(protocols),
                backgroundColor: [
                    '#4e73df', // Primary
                    '#1cc88a', // Success
                    '#36b9cc', // Info
                    '#f6c23e', // Warning
                    '#e74a3b', // Danger
                    '#858796', // Secondary
                    '#5a5c69', // Dark
                    '#6f42c1', // Purple
                    '#20c9a6', // Teal
                    '#fd7e14'  // Orange
                ],
                hoverOffset: 4
            }]
        };
        
        // Check if there is no data
        if (Object.keys(protocols).length === 0) {
            document.getElementById('no-protocol-data').classList.remove('d-none');
            document.getElementById('protocolChart').classList.add('d-none');
            return;
        } else {
            document.getElementById('no-protocol-data').classList.add('d-none');
            document.getElementById('protocolChart').classList.remove('d-none');
        }
        
        // Create or update chart
        if (protocolChart) {
            protocolChart.data = protocolData;
            protocolChart.update();
        } else {
            protocolChart = new Chart(protocolChartCtx, {
                type: 'doughnut',
                data: protocolData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.raw || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = Math.round((value / total) * 100);
                                    return `${label}: ${value} (${percentage}%)`;
                                }
                            }
                        }
                    }
                }
            });
        }
        
        // Create traffic over time chart (placeholder data)
        // In a real implementation, this would use real time-series data
        updateTrafficChart();
    }
    
    function updateTrafficChart() {
        // This would fetch real time-series data from an API endpoint
        // Using placeholder data for now
        
        const labels = [];
        const now = new Date();
        
        for (let i = 9; i >= 0; i--) {
            const time = new Date(now - i * 6 * 60000); // Every 6 minutes
            labels.push(time.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}));
        }
        
        // Sample data - in real app, this would come from the API
        const data = {
            labels: labels,
            datasets: [
                {
                    label: 'TCP',
                    data: [2.1, 2.3, 2.5, 3.8, 2.9, 2.6, 3.2, 3.5, 3.8, 4.1],
                    borderColor: '#4e73df',
                    backgroundColor: 'rgba(78, 115, 223, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'UDP',
                    data: [1.0, 1.1, 1.2, 1.0, 1.3, 1.4, 1.2, 1.3, 1.5, 1.4],
                    borderColor: '#1cc88a',
                    backgroundColor: 'rgba(28, 200, 138, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Other',
                    data: [0.3, 0.2, 0.4, 0.3, 0.5, 0.3, 0.2, 0.4, 0.3, 0.2],
                    borderColor: '#f6c23e',
                    backgroundColor: 'rgba(246, 194, 62, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        };
        
        // Create or update chart
        if (trafficChart) {
            trafficChart.data = data;
            trafficChart.update();
        } else {
            trafficChart = new Chart(trafficChartCtx, {
                type: 'line',
                data: data,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            grid: {
                                display: false
                            }
                        },
                        y: {
                            title: {
                                display: true,
                                text: 'MB'
                            },
                            beginAtZero: true
                        }
                    },
                    plugins: {
                        legend: {
                            position: 'top',
                        },
                        tooltip: {
                            mode: 'index',
                            intersect: false
                        }
                    }
                }
            });
        }
    }
    
    function loadRecentAlerts() {
        fetch('/api/alerts/recent')
            .then(response => response.json())
            .then(data => {
                const alertsList = document.getElementById('recent-alerts-list');
                
                if (data.length === 0) {
                    alertsList.innerHTML = `
                        <div class="text-center py-3">
                            <i class="fas fa-check-circle fa-3x text-success mb-3"></i>
                            <p>No alerts detected</p>
                        </div>
                    `;
                    return;
                }
                
                let alertsHtml = '';
                
                data.forEach(alert => {
                    // Determine alert styling based on severity
                    let alertClass = 'alert-secondary';
                    let iconClass = 'fa-info-circle';
                    
                    if (alert.severity === 'critical') {
                        alertClass = 'alert-danger';
                        iconClass = 'fa-skull-crossbones';
                    } else if (alert.severity === 'high') {
                        alertClass = 'alert-warning';
                        iconClass = 'fa-exclamation-circle';
                    } else if (alert.severity === 'medium') {
                        alertClass = 'alert-info';
                        iconClass = 'fa-exclamation-triangle';
                    }
                    
                    // Format timestamp
                    const alertTime = new Date(alert.timestamp);
                    const timeString = alertTime.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
                    
                    alertsHtml += `
                        <div class="alert ${alertClass} d-flex align-items-center">
                            <i class="fas ${iconClass} fa-lg me-3"></i>
                            <div>
                                <div class="fw-bold">${alert.alert_type.replace('_', ' ')}</div>
                                <div>${alert.message}</div>
                                <small class="text-muted">${timeString}</small>
                            </div>
                        </div>
                    `;
                });
                
                alertsList.innerHTML = alertsHtml;
            })
            .catch(error => {
                console.error('Error loading recent alerts:', error);
                const alertsList = document.getElementById('recent-alerts-list');
                alertsList.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        Error loading alerts
                    </div>
                `;
            });
    }
    
    function loadTopIPs() {
        fetch('/api/traffic/top_ips')
            .then(response => response.json())
            .then(data => {
                const ipsList = document.getElementById('top-ips-list');
                
                if (!data.source || data.source.length === 0) {
                    ipsList.innerHTML = `
                        <div class="text-center py-3">
                            <i class="fas fa-info-circle fa-3x text-info mb-3"></i>
                            <p>No IP data available yet</p>
                        </div>
                    `;
                    return;
                }
                
                let ipsHtml = `
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Traffic</th>
                                </tr>
                            </thead>
                            <tbody>
                `;
                
                // Show top 5 source IPs
                data.source.slice(0, 5).forEach(ip => {
                    ipsHtml += `
                        <tr>
                            <td>${ip.ip}</td>
                            <td>${ip.mb.toFixed(2)} MB</td>
                        </tr>
                    `;
                });
                
                ipsHtml += `
                            </tbody>
                        </table>
                    </div>
                `;
                
                ipsList.innerHTML = ipsHtml;
            })
            .catch(error => {
                console.error('Error loading top IPs:', error);
                const ipsList = document.getElementById('top-ips-list');
                ipsList.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        Error loading IP data
                    </div>
                `;
            });
    }
});
