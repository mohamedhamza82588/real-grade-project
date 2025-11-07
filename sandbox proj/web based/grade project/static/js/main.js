// ========================================
// NETWORK SECURITY SCANNER - MAIN JS
// Real-time Progress Updates & AJAX
// ========================================

let scanInterval = null;
let startTime = null;
let elapsedInterval = null;

// DOM Elements
const startScanBtn = document.getElementById('startScanBtn');
const progressSection = document.getElementById('progressSection');
const completionSection = document.getElementById('completionSection');
const progressBar = document.getElementById('progressBar');
const progressText = document.getElementById('progressText');
const statusMessage = document.getElementById('statusMessage');
const liveOutput = document.getElementById('liveOutput');

// Metric elements
const hostsDiscovered = document.getElementById('hostsDiscovered');
const portsScanned = document.getElementById('portsScanned');
const vulnsFound = document.getElementById('vulnsFound');
const elapsedTime = document.getElementById('elapsedTime');

// Start Scan Button Click
if (startScanBtn) {
    startScanBtn.addEventListener('click', startScan);
}

// Download Report Button
const downloadReportBtn = document.getElementById('downloadReportBtn');
if (downloadReportBtn) {
    downloadReportBtn.addEventListener('click', function() {
        window.location.href = '/download-report';
    });
}

// Start Scan Function
function startScan() {
    // Disable button
    startScanBtn.disabled = true;
    startScanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';

    // Send AJAX request to start scan
    fetch('/start-scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Show progress section
            progressSection.style.display = 'block';
            completionSection.style.display = 'none';

            // Reset progress
            updateProgress(0, 'Initializing scan...');
            liveOutput.innerHTML = '<code>Scan started...</code>';

            // Start tracking time
            startTime = Date.now();
            startElapsedTimer();

            // Start polling for status
            scanInterval = setInterval(pollScanStatus, 1000);
        } else {
            alert('Error: ' + data.message);
            startScanBtn.disabled = false;
            startScanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Failed to start scan');
        startScanBtn.disabled = false;
        startScanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
    });
}

// Poll Scan Status
function pollScanStatus() {
    fetch('/scan-status')
    .then(response => response.json())
    .then(status => {
        // Update progress bar
        updateProgress(status.progress, status.message);

        // Update live output
        if (status.live_output && status.live_output.length > 0) {
            const outputText = status.live_output.slice(-20).join('\n');
            liveOutput.innerHTML = '<code>' + escapeHtml(outputText) + '</code>';

            // Auto-scroll to bottom
            liveOutput.parentElement.scrollTop = liveOutput.parentElement.scrollHeight;

            // Parse metrics from output
            parseMetrics(status.live_output);
        }

        // Check if scan is complete
        if (!status.running && status.stage === 'completed') {
            clearInterval(scanInterval);
            clearInterval(elapsedInterval);
            onScanComplete();
        }

        // Check for errors
        if (status.stage === 'error') {
            clearInterval(scanInterval);
            clearInterval(elapsedInterval);
            onScanError(status.message);
        }
    })
    .catch(error => {
        console.error('Polling error:', error);
    });
}

// Update Progress Bar
function updateProgress(percent, message) {
    progressBar.style.width = percent + '%';
    progressText.textContent = Math.round(percent) + '%';
    statusMessage.textContent = message;

    // Change color based on progress
    if (percent >= 100) {
        progressBar.classList.remove('bg-success', 'bg-info', 'bg-warning');
        progressBar.classList.add('bg-success');
    } else if (percent >= 75) {
        progressBar.classList.remove('bg-success', 'bg-info', 'bg-warning');
        progressBar.classList.add('bg-info');
    } else if (percent >= 50) {
        progressBar.classList.remove('bg-success', 'bg-info', 'bg-warning');
        progressBar.classList.add('bg-warning');
    }
}

// Parse Metrics from Output
function parseMetrics(outputLines) {
    let hosts = 0;
    let ports = 0;
    let vulns = 0;

    outputLines.forEach(line => {
        // Count discovered hosts
        if (line.includes('✓') && line.includes('192.168.9.')) {
            hosts++;
        }

        // Count found ports
        if (line.includes('Found') && line.includes('open ports')) {
            const match = line.match(/(\d+) open ports/);
            if (match) {
                ports += parseInt(match[1]);
            }
        }

        // Count vulnerabilities
        if (line.includes('CRITICAL:') || line.includes('HIGH:') || line.includes('MEDIUM:')) {
            vulns++;
        }
    });

    // Animate counter updates
    animateValue(hostsDiscovered, parseInt(hostsDiscovered.textContent), hosts, 300);
    animateValue(portsScanned, parseInt(portsScanned.textContent), ports, 300);
    animateValue(vulnsFound, parseInt(vulnsFound.textContent), vulns, 300);
}

// Animate Number Counter
function animateValue(element, start, end, duration) {
    if (start === end) return;

    const range = end - start;
    const increment = range / (duration / 16);
    let current = start;

    const timer = setInterval(() => {
        current += increment;
        if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
            element.textContent = end;
            clearInterval(timer);
        } else {
            element.textContent = Math.round(current);
        }
    }, 16);
}

// Start Elapsed Timer
function startElapsedTimer() {
    elapsedInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        const minutes = Math.floor(elapsed / 60);
        const seconds = elapsed % 60;
        elapsedTime.textContent = minutes > 0 ? 
            `${minutes}m ${seconds}s` : `${seconds}s`;
    }, 1000);
}

// On Scan Complete
function onScanComplete() {
    updateProgress(100, 'Scan completed successfully!');

    // Show completion section
    setTimeout(() => {
        progressSection.style.display = 'none';
        completionSection.style.display = 'block';

        // Reset button
        startScanBtn.disabled = false;
        startScanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';

        // Refresh reports list
        loadRecentReports();
    }, 2000);
}

// On Scan Error
function onScanError(message) {
    alert('Scan error: ' + message);
    startScanBtn.disabled = false;
    startScanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
    progressSection.style.display = 'none';
}

// Load Recent Reports
function loadRecentReports() {
    fetch('/list-reports')
    .then(response => response.json())
    .then(reports => {
        const reportsTable = document.getElementById('reportsTable');

        if (reports.length === 0) {
            reportsTable.innerHTML = '<p class="text-muted text-center">No reports available yet</p>';
            return;
        }

        let html = '<table class="table table-hover"><thead><tr>';
        html += '<th>Report Name</th><th>Generated</th><th>Size</th><th>Actions</th>';
        html += '</tr></thead><tbody>';

        reports.forEach(report => {
            html += `<tr>
                <td><i class="fas fa-file-alt text-primary"></i> ${report.filename}</td>
                <td>${report.timestamp}</td>
                <td>${report.size}</td>
                <td>
                    <a href="/results" class="btn btn-sm btn-primary">
                        <i class="fas fa-eye"></i> View
                    </a>
                </td>
            </tr>`;
        });

        html += '</tbody></table>';
        reportsTable.innerHTML = html;
    })
    .catch(error => {
        console.error('Error loading reports:', error);
    });
}

// Escape HTML
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// Load reports on page load
document.addEventListener('DOMContentLoaded', function() {
    loadRecentReports();
});