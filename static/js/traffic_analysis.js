document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    const trafficVolumeChartCtx = document.getElementById('trafficVolumeChart').getContext('2d');
    const protocolDistributionChartCtx = document.getElementById('protocolDistributionChart').getContext('2d');
    const topApplicationsChartCtx = document.getElementById('topApplicationsChart').getContext('2d');
    
    let trafficVolumeChart = null;
    let protocolDistributionChart = null;
    let topApplicationsChart = null;
    
    // Current time filter (default: hour)
    let currentTimeFilter = 'hour';
    
    // Initialize page
    loadTrafficData();
    
    // Set up refresh button
    document.getElementById('refresh-traffic-btn').addEventListener('click', function() {
        loadTrafficData();
    });
    
    // Time filter dropdown handler
    document.querySelectorAll('[data-time]').forEach(item => {
        item.addEventListener('click', event => {
            currentTimeFilter = event.target.getAttribute('data-time');
            document.getElementById('time-filter-btn').textContent = event.target.textContent;
            loadTrafficData();
        });
    });
    
    // Table sort button handlers
    document.querySelectorAll('#sourceIpsTable .btn-group button').forEach(button => {
        button.addEventListener('click', function(e) {
            const sortBy = this.getAttribute('data-sort');
            document.querySelectorAll('#sourceIpsTable .btn-group button').forEach(btn => {
                btn.classList.remove('active');
            });
            this.classList.add('active');
            sortIPTable('source', sortBy);
        });
    });
    
    document.querySelectorAll('#destIpsTable .btn-group button').forEach(button => {
        button.addEventListener('click', function(e) {
            const sortBy = this.getAttribute('data-sort');
            document.querySelectorAll('#destIpsTable .btn-group button').forEach(btn => {
                btn.classList.remove('active');
            });
            this.classList.add('active');
            sortIPTable('destination', sortBy);
        });
    });
    
    // Functions
    function loadTrafficData() {
        // Show loading state
        document.getElementById('sourceIpsBody').innerHTML = '<tr><td colspan="4" class="text-center">Loading data...</td></tr>';
        document.getElementById('destIpsBody').innerHTML = '<tr><td colspan="4" class="text-center">Loading data...</td></tr>';
        document.getElementById('protocolsBody').innerHTML = '<tr><td colspan="5" class="text-center">Loading protocol data...</td></tr>';
        
        // Fetch top protocols
        fetch('/api/traffic/top_protocols')
            .then(response => response.json())
            .then(data => {
                updateProtocolDistributionChart(data);
                updateProtocolsTable(data);
                
                // Create a simulated application chart based on protocol data
                updateTopApplicationsChart(data);
            })
            .catch(error => {
                console.error('Error loading protocol data:', error);
            });
        
        // Fetch top IPs
        fetch('/api/traffic/top_ips')
            .then(response => response.json())
            .then(data => {
                updateIPTables(data);
            })
            .catch(error => {
                console.error('Error loading IP data:', error);
                document.getElementById('sourceIpsBody').innerHTML = '<tr><td colspan="4" class="text-center text-danger">Error loading data</td></tr>';
                document.getElementById('destIpsBody').innerHTML = '<tr><td colspan="4" class="text-center text-danger">Error loading data</td></tr>';
            });
        
        // Create traffic volume chart with time-series data
        // In a real implementation, this would fetch from a specific endpoint
        updateTrafficVolumeChart();
    }
    
    function updateTrafficVolumeChart() {
        // This would fetch real time-series data from an API endpoint
        // Using placeholder data for demonstration
        
        const labels = [];
        const now = new Date();
        let timeStep, pointCount;
        
        // Adjust time parameters based on filter
        if (currentTimeFilter === 'hour') {
            timeStep = 5 * 60000; // 5 minutes
            pointCount = 12;
        } else if (currentTimeFilter === 'day') {
            timeStep = 60 * 60000; // 1 hour
            pointCount = 24;
        } else if (currentTimeFilter === 'week') {
            timeStep = 6 * 60 * 60000; // 6 hours
            pointCount = 28;
        }
        
        for (let i = pointCount - 1; i >= 0; i--) {
            const time = new Date(now - i * timeStep);
            if (currentTimeFilter === 'hour') {
                labels.push(time.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}));
            } else if (currentTimeFilter === 'day') {
                labels.push(time.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}));
            } else {
                labels.push(time.toLocaleDateString([], {weekday: 'short', hour: '2-digit'}));
            }
        }
        
        // Generate deterministic but varying data
        const generateData = (seed, variability) => {
            return Array.from({length: pointCount}, (_, i) => {
                // Use a simple pseudorandom function based on index
                const randomFactor = Math.sin(i * seed) * variability;
                return Math.max(0, seed + randomFactor).toFixed(2);
            });
        };
        
        const data = {
            labels: labels,
            datasets: [
                {
                    label: 'Inbound',
                    data: generateData(3, 1.5),
                    borderColor: '#4e73df',
                    backgroundColor: 'rgba(78, 115, 223, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Outbound',
                    data: generateData(2, 1.2),
                    borderColor: '#1cc88a',
                    backgroundColor: 'rgba(28, 200, 138, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Total',
                    data: generateData(5, 2),
                    borderColor: '#f6c23e',
                    backgroundColor: 'rgba(246, 194, 62, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        };
        
        // Create or update chart
        if (trafficVolumeChart) {
            trafficVolumeChart.data = data;
            trafficVolumeChart.update();
        } else {
            trafficVolumeChart = new Chart(trafficVolumeChartCtx, {
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
                                text: 'MB/s'
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
    
    function updateProtocolDistributionChart(protocols) {
        // Extract data for the chart
        const labels = protocols.map(p => p.protocol);
        const data = protocols.map(p => p.bytes);
        
        const chartData = {
            labels: labels,
            datasets: [{
                data: data,
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
        
        // Create or update chart
        if (protocolDistributionChart) {
            protocolDistributionChart.data = chartData;
            protocolDistributionChart.update();
        } else {
            protocolDistributionChart = new Chart(protocolDistributionChartCtx, {
                type: 'doughnut',
                data: chartData,
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
                                    const mbValue = (value / (1024 * 1024)).toFixed(2);
                                    return `${label}: ${mbValue} MB (${percentage}%)`;
                                }
                            }
                        }
                    }
                }
            });
        }
    }
    
    function updateTopApplicationsChart(protocols) {
        // Create application grouping from protocols
        // In a real implementation, this would come from a dedicated API
        const applications = [];
        
        // Map common protocols to applications
        protocols.forEach(protocol => {
            let appName;
            if (protocol.protocol.includes('TCP (Port 80)') || protocol.protocol.includes('TCP (Port 443)')) {
                appName = 'Web Browsing';
            } else if (protocol.protocol.includes('UDP (Port 53)') || protocol.protocol.includes('TCP (Port 53)')) {
                appName = 'DNS';
            } else if (protocol.protocol.includes('TCP (Port 22)')) {
                appName = 'SSH';
            } else if (protocol.protocol.includes('UDP (Port 123)')) {
                appName = 'NTP';
            } else if (protocol.protocol.includes('ICMP')) {
                appName = 'ICMP';
            } else if (protocol.protocol.includes('TCP (Port 25)') || protocol.protocol.includes('TCP (Port 587)') || protocol.protocol.includes('TCP (Port 465)')) {
                appName = 'Email';
            } else if (protocol.protocol.includes('UDP')) {
                appName = 'Other UDP';
            } else if (protocol.protocol.includes('TCP')) {
                appName = 'Other TCP';
            } else {
                appName = 'Other';
            }
            
            // Find if application already exists in our array
            const existingApp = applications.find(app => app.name === appName);
            if (existingApp) {
                existingApp.bytes += protocol.bytes;
            } else {
                applications.push({
                    name: appName,
                    bytes: protocol.bytes
                });
            }
        });
        
        // Sort by bytes
        applications.sort((a, b) => b.bytes - a.bytes);
        
        // Take top 6 applications
        const topApps = applications.slice(0, 6);
        
        // Extract data for the chart
        const labels = topApps.map(a => a.name);
        const data = topApps.map(a => a.bytes);
        
        const barColors = [
            'rgba(78, 115, 223, 0.8)',
            'rgba(28, 200, 138, 0.8)',
            'rgba(54, 185, 204, 0.8)',
            'rgba(246, 194, 62, 0.8)',
            'rgba(231, 74, 59, 0.8)',
            'rgba(133, 135, 150, 0.8)'
        ];
        
        const chartData = {
            labels: labels,
            datasets: [{
                label: 'Data Usage',
                data: data,
                backgroundColor: barColors,
                borderColor: barColors.map(color => color.replace('0.8', '1')),
                borderWidth: 1
            }]
        };
        
        // Create or update chart
        if (topApplicationsChart) {
            topApplicationsChart.data = chartData;
            topApplicationsChart.update();
        } else {
            topApplicationsChart = new Chart(topApplicationsChartCtx, {
                type: 'bar',
                data: chartData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Bytes'
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const value = context.raw || 0;
                                    const mbValue = (value / (1024 * 1024)).toFixed(2);
                                    return `${mbValue} MB`;
                                }
                            }
                        }
                    }
                }
            });
        }
    }
    
    function updateIPTables(data) {
        // Update source IPs table
        updateIPTable('sourceIpsBody', data.source);
        
        // Update destination IPs table
        updateIPTable('destIpsBody', data.destination);
    }
    
    function updateIPTable(tableId, ips) {
        const tableBody = document.getElementById(tableId);
        if (!ips || ips.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="4" class="text-center">No data available</td></tr>';
            return;
        }
        
        // Calculate total bytes for percentage
        const totalBytes = ips.reduce((sum, ip) => sum + ip.bytes, 0);
        
        let html = '';
        ips.forEach(ip => {
            const percentage = ((ip.bytes / totalBytes) * 100).toFixed(1);
            html += `
                <tr>
                    <td>${ip.ip}</td>
                    <td>${ip.packet_count.toLocaleString()}</td>
                    <td>${ip.mb.toFixed(2)} MB</td>
                    <td>
                        <div class="d-flex align-items-center">
                            <span class="me-2">${percentage}%</span>
                            <div class="progress flex-grow-1" style="height: 8px;">
                                <div class="progress-bar" role="progressbar" style="width: ${percentage}%"></div>
                            </div>
                        </div>
                    </td>
                </tr>
            `;
        });
        
        tableBody.innerHTML = html;
    }
    
    function sortIPTable(type, sortBy) {
        // This would normally refetch data with a sort parameter
        // For now, we'll just simulate by re-sorting the displayed table
        
        const tableId = type === 'source' ? 'sourceIpsTable' : 'destIpsTable';
        const rows = Array.from(document.querySelectorAll(`#${tableId} tbody tr`));
        
        // Skip if we're in a loading or error state
        if (rows.length === 1 && rows[0].cells.length < 3) {
            return;
        }
        
        // Sort rows based on criteria
        rows.sort((a, b) => {
            if (sortBy === 'bytes') {
                // Extract MB values
                const valueA = parseFloat(a.cells[2].textContent);
                const valueB = parseFloat(b.cells[2].textContent);
                return valueB - valueA; // Descending order
            } else {
                // Sort by packet count
                const valueA = parseInt(a.cells[1].textContent.replace(/,/g, ''));
                const valueB = parseInt(b.cells[1].textContent.replace(/,/g, ''));
                return valueB - valueA; // Descending order
            }
        });
        
        // Re-add rows in the sorted order
        const tbody = document.querySelector(`#${tableId} tbody`);
        rows.forEach(row => tbody.appendChild(row));
    }
    
    function updateProtocolsTable(protocols) {
        const tableBody = document.getElementById('protocolsBody');
        if (!protocols || protocols.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="5" class="text-center">No protocol data available</td></tr>';
            return;
        }
        
        // Calculate total bytes for percentage
        const totalBytes = protocols.reduce((sum, p) => sum + p.bytes, 0);
        
        let html = '';
        protocols.forEach((protocol, index) => {
            const percentage = ((protocol.bytes / totalBytes) * 100).toFixed(1);
            // Generate trend arrow (this would be based on real trend data in a full implementation)
            const trends = ['up', 'down', 'stable'];
            const trend = trends[index % 3];
            let trendHtml = '';
            
            if (trend === 'up') {
                trendHtml = '<span class="text-success"><i class="fas fa-arrow-up me-1"></i>8%</span>';
            } else if (trend === 'down') {
                trendHtml = '<span class="text-danger"><i class="fas fa-arrow-down me-1"></i>5%</span>';
            } else {
                trendHtml = '<span class="text-secondary"><i class="fas fa-minus me-1"></i>0%</span>';
            }
            
            html += `
                <tr>
                    <td>${protocol.protocol}</td>
                    <td>${protocol.packet_count.toLocaleString()}</td>
                    <td>${protocol.mb.toFixed(2)} MB</td>
                    <td>
                        <div class="d-flex align-items-center">
                            <span class="me-2">${percentage}%</span>
                            <div class="progress flex-grow-1" style="height: 8px;">
                                <div class="progress-bar" role="progressbar" style="width: ${percentage}%"></div>
                            </div>
                        </div>
                    </td>
                    <td>${trendHtml}</td>
                </tr>
            `;
        });
        
        tableBody.innerHTML = html;
    }
});
