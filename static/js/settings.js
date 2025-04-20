document.addEventListener('DOMContentLoaded', function() {
    // Initialize page
    refreshSystemInfo();
    
    // Set up form submission handlers
    document.getElementById('capture-settings-form').addEventListener('submit', function(e) {
        e.preventDefault();
        saveCaptureSettings();
    });
    
    document.getElementById('storage-settings-form').addEventListener('submit', function(e) {
        e.preventDefault();
        saveStorageSettings();
    });
    
    document.getElementById('alert-settings-form').addEventListener('submit', function(e) {
        e.preventDefault();
        saveAlertSettings();
    });
    
    document.getElementById('display-settings-form').addEventListener('submit', function(e) {
        e.preventDefault();
        saveDisplaySettings();
    });
    
    document.getElementById('password-change-form').addEventListener('submit', function(e) {
        e.preventDefault();
        changePassword();
    });
    
    // Set up system refresh button
    document.getElementById('system-refresh-btn').addEventListener('click', function() {
        refreshSystemInfo();
    });
    
    // Functions
    function saveCaptureSettings() {
        const settings = {
            interface: document.getElementById('interface-select').value,
            filter: document.getElementById('capture-filter').value,
            buffer_size: document.getElementById('packet-buffer').value,
            auto_start: document.getElementById('auto-start-capture').checked
        };
        
        // Simulate saving - in a real app, this would be an API call
        simulateSuccessMessage('Capture settings saved successfully!');
    }
    
    function saveStorageSettings() {
        const settings = {
            retention_days: document.getElementById('db-retention').value,
            auto_clean: document.getElementById('auto-clean-db').checked
        };
        
        // Simulate saving - in a real app, this would be an API call
        simulateSuccessMessage('Storage settings saved successfully!');
    }
    
    function saveAlertSettings() {
        const settings = {
            port_scan_detection: document.getElementById('port-scan-detection').checked,
            syn_flood_detection: document.getElementById('syn-flood-detection').checked,
            traffic_spike_detection: document.getElementById('traffic-spike-detection').checked,
            unusual_protocol_detection: document.getElementById('unusual-protocol-detection').checked,
            port_scan_threshold: document.getElementById('port-scan-threshold').value,
            syn_flood_threshold: document.getElementById('syn-flood-threshold').value,
            traffic_spike_factor: document.getElementById('traffic-spike-factor').value
        };
        
        // Simulate saving - in a real app, this would be an API call
        simulateSuccessMessage('Alert settings saved successfully!');
    }
    
    function saveDisplaySettings() {
        const settings = {
            refresh_interval: document.getElementById('refresh-interval').value,
            chart_time_window: document.getElementById('chart-time-window').value,
            show_hostname: document.getElementById('show-hostname').checked,
            show_port_service: document.getElementById('show-port-service').checked
        };
        
        // Simulate saving - in a real app, this would be an API call
        simulateSuccessMessage('Display settings saved successfully!');
    }
    
    function changePassword() {
        const currentPassword = document.getElementById('current-password').value;
        const newPassword = document.getElementById('new-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        
        // Validate passwords
        if (!currentPassword || !newPassword || !confirmPassword) {
            showError('All password fields are required');
            return;
        }
        
        if (newPassword !== confirmPassword) {
            showError('New passwords do not match');
            return;
        }
        
        if (newPassword.length < 8) {
            showError('Password must be at least 8 characters long');
            return;
        }
        
        if (!newPassword.match(/[A-Za-z]/) || !newPassword.match(/[0-9]/)) {
            showError('Password must contain at least one letter and one number');
            return;
        }
        
        // Simulate password change - in a real app, this would be an API call
        simulateSuccessMessage('Password changed successfully!');
        
        // Clear form
        document.getElementById('password-change-form').reset();
    }
    
    function refreshSystemInfo() {
        // In a real implementation, this would fetch system data from an API
        // For now, we'll simulate the data
        
        // Simulate DB size
        const dbSize = (Math.random() * 10 + 2).toFixed(2);
        document.getElementById('db-size').textContent = `${dbSize} MB`;
        
        // Simulate uptime
        const days = Math.floor(Math.random() * 10) + 1;
        const hours = Math.floor(Math.random() * 24);
        const minutes = Math.floor(Math.random() * 60);
        document.getElementById('system-uptime').textContent = `${days} days, ${hours} hours, ${minutes} minutes`;
        
        // Simulate CPU usage
        const cpuUsage = (Math.random() * 30 + 5).toFixed(1);
        document.getElementById('cpu-usage').textContent = `${cpuUsage}%`;
        
        // Simulate memory usage
        const memoryUsageMB = Math.floor(Math.random() * 200 + 100);
        const memoryTotalMB = 1024;
        const memoryPercent = (memoryUsageMB / memoryTotalMB * 100).toFixed(1);
        document.getElementById('memory-usage').textContent = `${memoryUsageMB} MB / ${memoryTotalMB} MB (${memoryPercent}%)`;
    }
    
    function simulateSuccessMessage(message) {
        // Create alert element
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-success alert-dismissible fade show';
        alertDiv.role = 'alert';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Find the active tab pane
        const activePane = document.querySelector('.tab-pane.active');
        
        // Insert at the top of the active pane
        activePane.insertBefore(alertDiv, activePane.firstChild);
        
        // Automatically remove after 3 seconds
        setTimeout(() => {
            alertDiv.classList.remove('show');
            setTimeout(() => alertDiv.remove(), 150);
        }, 3000);
    }
    
    function showError(message) {
        // Create alert element
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-danger alert-dismissible fade show';
        alertDiv.role = 'alert';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Find the active tab pane
        const activePane = document.querySelector('.tab-pane.active');
        
        // Insert at the top of the active pane
        activePane.insertBefore(alertDiv, activePane.firstChild);
        
        // Automatically remove after 5 seconds
        setTimeout(() => {
            alertDiv.classList.remove('show');
            setTimeout(() => alertDiv.remove(), 150);
        }, 5000);
    }
});
