document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    const alertTypesChartCtx = document.getElementById('alertTypesChart').getContext('2d');
    const alertTimelineChartCtx = document.getElementById('alertTimelineChart').getContext('2d');
    
    let alertTypesChart = null;
    let alertTimelineChart = null;
    
    // Current filter (default: all)
    let currentFilter = 'all';
    
    // Initialize page
    loadAlerts();
    
    // Set up refresh button
    document.getElementById('refresh-alerts-btn').addEventListener('click', function() {
        loadAlerts();
    });
    
    // Filter dropdown handler
    document.querySelectorAll('[data-filter]').forEach(item => {
        item.addEventListener('click', event => {
            currentFilter = event.target.getAttribute('data-filter');
            document.getElementById('filter-alerts-btn').textContent = event.target.textContent;
            filterAlerts(currentFilter);
        });
    });
    
    // Functions
    function loadAlerts() {
        // Show loading state
        document.getElementById('alertsTableBody').innerHTML = `
            <tr>
                <td colspan="8" class="text-center">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                    <p class="mt-2">Loading alerts...</p>
                </td>
            </tr>
        `;
        
        // Get all alerts (we'll filter client-side)
        fetch('/api/alerts/recent?limit=100')
            .then(response => response.json())
            .then(data => {
                // Store alerts globally for filtering
                window.allAlerts = data;
                
                // Display alerts based on current filter
                filterAlerts(currentFilter);
                
                // Update alert summary cards
                updateAlertSummary(data);
                
                // Create charts
                createAlertCharts(data);
            })
            .catch(error => {
                console.error('Error loading alerts:', error);
                document.getElementById('alertsTableBody').innerHTML = `
                    <tr>
                        <td colspan="8" class="text-center text-danger">
                            <i class="fas fa-exclamation-circle me-2"></i> Error loading alerts
                        </td>
                    </tr>
                `;
            });
    }
    
    function filterAlerts(filter) {
        if (!window.allAlerts) {
            return; // Data not loaded yet
        }
        
        let filteredAlerts = [...window.allAlerts];
        
        // Apply filters
        if (filter === 'critical') {
            filteredAlerts = filteredAlerts.filter(alert => alert.severity === 'critical');
        } else if (filter === 'high') {
            filteredAlerts = filteredAlerts.filter(alert => 
                alert.severity === 'critical' || alert.severity === 'high');
        } else if (filter === 'unresolved') {
            filteredAlerts = filteredAlerts.filter(alert => !alert.resolved);
        }
        
        displayAlerts(filteredAlerts);
    }
    
    function displayAlerts(alerts) {
        const tableBody = document.getElementById('alertsTableBody');
        const alertsCount = document.getElementById('alerts-count-badge');
        const noAlerts = document.getElementById('no-alerts');
        
        if (alerts.length === 0) {
            tableBody.innerHTML = '';
            alertsCount.textContent = '0 alerts';
            noAlerts.classList.remove('d-none');
            return;
        }
        
        noAlerts.classList.add('d-none');
        alertsCount.textContent = `${alerts.length} alert${alerts.length > 1 ? 's' : ''}`;
        
        let html = '';
        
        alerts.forEach(alert => {
            // Format timestamp
            const timestamp = new Date(alert.timestamp);
            const timeString = timestamp.toLocaleString([], {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
            
            // Determine severity badge
            let severityBadge = '';
            if (alert.severity === 'critical') {
                severityBadge = '<span class="badge bg-danger">Critical</span>';
            } else if (alert.severity === 'high') {
                severityBadge = '<span class="badge bg-warning text-dark">High</span>';
            } else if (alert.severity === 'medium') {
                severityBadge = '<span class="badge bg-info">Medium</span>';
            } else {
                severityBadge = '<span class="badge bg-secondary">Low</span>';
            }
            
            // Format alert type
            const alertType = alert.alert_type.replace(/_/g, ' ');
            
            // Status badge
            const statusBadge = alert.resolved ? 
                '<span class="badge bg-success">Resolved</span>' :
                '<span class="badge bg-warning text-dark">Active</span>';
            
            html += `
                <tr>
                    <td>${timeString}</td>
                    <td>${alertType}</td>
                    <td>${severityBadge}</td>
                    <td>${alert.source_ip || '-'}</td>
                    <td>${alert.destination_ip || '-'}</td>
                    <td>${alert.message}</td>
                    <td>${statusBadge}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary view-alert-btn" data-alert-id="${alert.id}">
                            <i class="fas fa-search"></i>
                        </button>
                    </td>
                </tr>
            `;
        });
        
        tableBody.innerHTML = html;
        
        // Add event listeners to view buttons
        document.querySelectorAll('.view-alert-btn').forEach(button => {
            button.addEventListener('click', function() {
                const alertId = this.getAttribute('data-alert-id');
                showAlertDetails(alertId);
            });
        });
    }
    
    function showAlertDetails(alertId) {
        // Find the alert in our data
        const alert = window.allAlerts.find(a => a.id == alertId);
        
        if (!alert) {
            console.error('Alert not found:', alertId);
            return;
        }
        
        // Format timestamp
        const timestamp = new Date(alert.timestamp);
        const timeString = timestamp.toLocaleString();
        
        // Set modal content
        document.getElementById('alert-id').textContent = alert.id;
        document.getElementById('alert-type').textContent = alert.alert_type.replace(/_/g, ' ');
        document.getElementById('alert-time').textContent = timeString;
        document.getElementById('alert-status').textContent = alert.resolved ? 'Resolved' : 'Active';
        document.getElementById('alert-source').textContent = alert.source_ip || 'N/A';
        document.getElementById('alert-destination').textContent = alert.destination_ip || 'N/A';
        document.getElementById('alert-message').textContent = alert.message;
        document.getElementById('alert-details').textContent = alert.details || 'No additional details available';
        
        // Set severity indicator
        const severityIndicator = document.getElementById('alert-severity-indicator');
        const severityText = document.getElementById('alert-severity-text');
        
        severityIndicator.className = 'alert d-flex align-items-center mb-4';
        if (alert.severity === 'critical') {
            severityIndicator.classList.add('alert-danger');
            severityText.textContent = 'Critical Alert';
        } else if (alert.severity === 'high') {
            severityIndicator.classList.add('alert-warning');
            severityText.textContent = 'High Alert';
        } else if (alert.severity === 'medium') {
            severityIndicator.classList.add('alert-info');
            severityText.textContent = 'Medium Alert';
        } else {
            severityIndicator.classList.add('alert-secondary');
            severityText.textContent = 'Low Alert';
        }
        
        // Configure resolve button
        const resolveBtn = document.getElementById('resolve-alert-btn');
        if (alert.resolved) {
            resolveBtn.disabled = true;
            resolveBtn.textContent = 'Already Resolved';
        } else {
            resolveBtn.disabled = false;
            resolveBtn.textContent = 'Mark as Resolved';
            
            // Reset event listeners
            resolveBtn.replaceWith(resolveBtn.cloneNode(true));
            document.getElementById('resolve-alert-btn').addEventListener('click', function() {
                resolveAlert(alert.id);
            });
        }
        
        // Show the modal
        const alertDetailModal = new bootstrap.Modal(document.getElementById('alertDetailModal'));
        alertDetailModal.show();
    }
    
    function resolveAlert(alertId) {
        // In a real implementation, this would call an API endpoint
        // For now we'll just modify our local data
        const alert = window.allAlerts.find(a => a.id == alertId);
        if (alert) {
            alert.resolved = true;
            
            // Update UI
            const resolveBtn = document.getElementById('resolve-alert-btn');
            resolveBtn.disabled = true;
            resolveBtn.textContent = 'Alert Resolved';
            
            document.getElementById('alert-status').textContent = 'Resolved';
            
            // Re-filter the table
            filterAlerts(currentFilter);
        }
    }
    
    function updateAlertSummary(alerts) {
        // Count alerts by severity
        const counts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };
        
        alerts.forEach(alert => {
            counts[alert.severity] = (counts[alert.severity] || 0) + 1;
        });
        
        // Update summary cards
        document.getElementById('critical-alerts-count').textContent = counts.critical;
        document.getElementById('high-alerts-count').textContent = counts.high;
        document.getElementById('medium-alerts-count').textContent = counts.medium;
        document.getElementById('low-alerts-count').textContent = counts.low;
    }
    
    function createAlertCharts(alerts) {
        createAlertTypesChart(alerts);
        createAlertTimelineChart(alerts);
    }
    
    function createAlertTypesChart(alerts) {
        // Group alerts by type
        const typeCount = {};
        alerts.forEach(alert => {
            const type = alert.alert_type;
            typeCount[type] = (typeCount[type] || 0) + 1;
        });
        
        const labels = Object.keys(typeCount).map(type => type.replace(/_/g, ' '));
        const data = Object.values(typeCount);
        
        const chartColors = [
            '#e74a3b', // Danger
            '#f6c23e', // Warning
            '#36b9cc', // Info
            '#4e73df', // Primary
            '#1cc88a', // Success
            '#858796'  // Secondary
        ];
        
        const chartData = {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: chartColors.slice(0, labels.length),
                hoverOffset: 4
            }]
        };
        
        // Create or update chart
        if (alertTypesChart) {
            alertTypesChart.data = chartData;
            alertTypesChart.update();
        } else {
            alertTypesChart = new Chart(alertTypesChartCtx, {
                type: 'doughnut',
                data: chartData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                        }
                    }
                }
            });
        }
    }
    
    function createAlertTimelineChart(alerts) {
        // Sort alerts by timestamp
        alerts.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        
        // Create time buckets (last 24 hours in 2-hour intervals)
        const now = new Date();
        const buckets = [];
        const bucketLabels = [];
        
        for (let i = 11; i >= 0; i--) {
            const bucketEnd = new Date(now - i * 2 * 60 * 60 * 1000);
            const bucketStart = new Date(bucketEnd - 2 * 60 * 60 * 1000);
            
            // Format label as "HH:MM"
            bucketLabels.push(bucketEnd.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}));
            
            // Count alerts in this time bucket
            buckets.push({
                startTime: bucketStart,
                endTime: bucketEnd,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0
            });
        }
        
        // Count alerts per bucket and severity
        alerts.forEach(alert => {
            const alertTime = new Date(alert.timestamp);
            
            for (let i = 0; i < buckets.length; i++) {
                if (alertTime >= buckets[i].startTime && alertTime < buckets[i].endTime) {
                    buckets[i][alert.severity]++;
                    break;
                }
            }
        });
        
        // Prepare chart data
        const chartData = {
            labels: bucketLabels,
            datasets: [
                {
                    label: 'Critical',
                    data: buckets.map(b => b.critical),
                    backgroundColor: '#e74a3b',
                    borderColor: '#e74a3b',
                    borderWidth: 1
                },
                {
                    label: 'High',
                    data: buckets.map(b => b.high),
                    backgroundColor: '#f6c23e',
                    borderColor: '#f6c23e',
                    borderWidth: 1
                },
                {
                    label: 'Medium',
                    data: buckets.map(b => b.medium),
                    backgroundColor: '#36b9cc',
                    borderColor: '#36b9cc',
                    borderWidth: 1
                },
                {
                    label: 'Low',
                    data: buckets.map(b => b.low),
                    backgroundColor: '#858796',
                    borderColor: '#858796',
                    borderWidth: 1
                }
            ]
        };
        
        // Create or update chart
        if (alertTimelineChart) {
            alertTimelineChart.data = chartData;
            alertTimelineChart.update();
        } else {
            alertTimelineChart = new Chart(alertTimelineChartCtx, {
                type: 'bar',
                data: chartData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            stacked: true
                        },
                        y: {
                            stacked: true,
                            beginAtZero: true
                        }
                    },
                    plugins: {
                        tooltip: {
                            mode: 'index',
                            intersect: false
                        }
                    }
                }
            });
        }
    }
});
