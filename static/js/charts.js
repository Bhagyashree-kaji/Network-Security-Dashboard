// Common chart utility functions

// Color palette
const chartColors = {
    primary: '#4e73df',
    success: '#1cc88a',
    info: '#36b9cc',
    warning: '#f6c23e',
    danger: '#e74a3b',
    secondary: '#858796',
    dark: '#5a5c69',
    primaryLight: 'rgba(78, 115, 223, 0.1)',
    successLight: 'rgba(28, 200, 138, 0.1)',
    infoLight: 'rgba(54, 185, 204, 0.1)',
    warningLight: 'rgba(246, 194, 62, 0.1)',
    dangerLight: 'rgba(231, 74, 59, 0.1)',
    palette: [
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
    ]
};

// Default chart options
const chartDefaults = {
    doughnut: {
        cutout: '70%',
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
                        return `${label}: ${value.toLocaleString()} (${percentage}%)`;
                    }
                }
            }
        }
    },
    line: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            x: {
                grid: {
                    display: false
                }
            },
            y: {
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
    },
    bar: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: {
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
};

// Helper for creating charts
function createChart(ctx, type, data, customOptions = {}) {
    const defaultOptions = chartDefaults[type] || {};
    
    return new Chart(ctx, {
        type: type,
        data: data,
        options: {
            ...defaultOptions,
            ...customOptions
        }
    });
}

// Time series data generators
function generateTimeLabels(count, interval = 'minutes') {
    const now = new Date();
    const labels = [];
    
    for (let i = count - 1; i >= 0; i--) {
        let time;
        
        if (interval === 'minutes') {
            time = new Date(now - i * 5 * 60000); // Every 5 minutes
            labels.push(time.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}));
        } else if (interval === 'hours') {
            time = new Date(now - i * 60 * 60000); // Every hour
            labels.push(time.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}));
        } else if (interval === 'days') {
            time = new Date(now - i * 24 * 60 * 60000); // Every day
            labels.push(time.toLocaleDateString([], {month: 'short', day: 'numeric'}));
        }
    }
    
    return labels;
}

// Format bytes as human-readable
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
}

// Format numbers with comma separators
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// Generate unique colors for chart entries
function getUniqueColors(count) {
    // If we have enough colors in our palette, use those
    if (count <= chartColors.palette.length) {
        return chartColors.palette.slice(0, count);
    }
    
    // Otherwise, generate colors with reasonable spacing
    const colors = [];
    for (let i = 0; i < count; i++) {
        const hue = (i * 137) % 360; // Golden angle approximation for good color distribution
        colors.push(`hsl(${hue}, 70%, 60%)`);
    }
    return colors;
}

// Data smoothing for time series
function smoothData(data, factor = 0.3) {
    if (!data || data.length <= 2) return data;
    
    const result = [data[0]];
    for (let i = 1; i < data.length - 1; i++) {
        const prev = result[i - 1];
        const current = data[i];
        const next = data[i + 1];
        
        // Simple moving average
        result.push(prev * factor + current * (1 - 2 * factor) + next * factor);
    }
    result.push(data[data.length - 1]);
    
    return result;
}

// Chart update with animation
function updateChartWithAnimation(chart, newData) {
    // Update datasets while keeping colors
    chart.data.labels = newData.labels || chart.data.labels;
    
    newData.datasets.forEach((dataset, i) => {
        if (chart.data.datasets[i]) {
            // Keep existing colors/styles
            const currentDataset = chart.data.datasets[i];
            Object.assign(currentDataset, dataset);
            
            // Preserve style attributes
            if (currentDataset.backgroundColor && !dataset.backgroundColor) {
                chart.data.datasets[i].backgroundColor = currentDataset.backgroundColor;
            }
            if (currentDataset.borderColor && !dataset.borderColor) {
                chart.data.datasets[i].borderColor = currentDataset.borderColor;
            }
        } else {
            // New dataset
            chart.data.datasets.push(dataset);
        }
    });
    
    // Remove extra datasets
    if (chart.data.datasets.length > newData.datasets.length) {
        chart.data.datasets.splice(newData.datasets.length);
    }
    
    chart.update();
}
