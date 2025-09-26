document.addEventListener("DOMContentLoaded", function() {

    const mobileMenuToggle = document.getElementById('mobileMenuToggle');
    const mobileMenuBtn = document.getElementById('mobileMenuBtn');
    const sidebar = document.getElementById('sidebar');
    
    if (mobileMenuToggle) {
        mobileMenuToggle.addEventListener('click', function() {
            sidebar.classList.add('active');
        });
    }
    
    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener('click', function() {
            sidebar.classList.remove('active');
        });
    }
    

    document.addEventListener('click', function(e) {
        if (window.innerWidth <= 768) {
            if (!sidebar.contains(e.target) && !mobileMenuToggle.contains(e.target)) {
                sidebar.classList.remove('active');
            }
        }
    });
    

    const scanForm = document.getElementById('scanForm');
    const startScanBtn = document.getElementById('startScanBtn');
    const stopScanBtn = document.getElementById('stopScanBtn');
    const scanProgress = document.getElementById('scanProgress');
    const findingsSection = document.getElementById('findingsSection');
    const scanResults = document.getElementById('scanResults');
    
    let scanInterval;
    let scanStartTime;
    let currentProgress = 0;
    let findings = [];
    

    function showAlert(message, type = 'info') {
        const alertContainer = document.getElementById('alertContainer');
        const alert = document.createElement('div');
        alert.className = `alert alert-${type} fade-in`;
        alert.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : type === 'warning' ? 'exclamation-triangle' : 'info-circle'}"></i>
            ${message}
            <button type="button" class="alert-close" onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;
        alertContainer.appendChild(alert);
        

        setTimeout(() => {
            if (alert.parentElement) {
                alert.remove();
            }
        }, 5000);
    }
    

    function updateProgress(percentage, status) {
        const progressFill = document.getElementById('progressFill');
        const progressPercentage = document.getElementById('progressPercentage');
        const progressStatus = document.getElementById('progressStatus');
        
        if (progressFill) progressFill.style.width = percentage + '%';
        if (progressPercentage) progressPercentage.textContent = percentage + '%';
        if (progressStatus) progressStatus.textContent = status;
    }
    

    function updateElapsedTime() {
        if (!scanStartTime) return;
        
        const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
        const minutes = Math.floor(elapsed / 60);
        const seconds = elapsed % 60;
        const timeString = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        
        const elapsedTimeElement = document.getElementById('elapsedTime');
        if (elapsedTimeElement) elapsedTimeElement.textContent = timeString;
    }
    

    function addFinding(finding) {
        findings.push(finding);
        
        const findingsList = document.getElementById('findingsList');
        const findingItem = document.createElement('div');
        findingItem.className = `finding-item ${finding.severity.toLowerCase()} slide-in`;
        findingItem.innerHTML = `
            <div class="finding-header">
                <span class="finding-severity ${finding.severity.toLowerCase()}">${finding.severity}</span>
                <span class="finding-time">${new Date().toLocaleTimeString()}</span>
            </div>
            <h4>${finding.type}</h4>
            <p><strong>Resource:</strong> ${finding.resource}</p>
            <p>${finding.description}</p>
        `;
        
        if (findingsList) {
            findingsList.appendChild(findingItem);
            findingsList.scrollTop = findingsList.scrollHeight;
        }
        

        updateFindingCounts();
    }
    

    function updateFindingCounts() {
        const highCount = findings.filter(f => f.severity === 'HIGH').length;
        const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
        const lowCount = findings.filter(f => f.severity === 'LOW').length;
        
        const highElement = document.getElementById('highFindings');
        const mediumElement = document.getElementById('mediumFindings');
        const lowElement = document.getElementById('lowFindings');
        const totalElement = document.getElementById('findingsCount');
        
        if (highElement) highElement.textContent = highCount;
        if (mediumElement) mediumElement.textContent = mediumCount;
        if (lowElement) lowElement.textContent = lowCount;
        if (totalElement) totalElement.textContent = findings.length;
    }
    

    function simulateScan() {
        const scanSteps = [
            { progress: 10, status: 'Initializing scan...', duration: 2000 },
            { progress: 25, status: 'Connecting to AWS...', duration: 3000 },
            { progress: 40, status: 'Scanning S3 buckets...', duration: 4000 },
            { progress: 55, status: 'Checking IAM policies...', duration: 3000 },
            { progress: 70, status: 'Analyzing VPC configuration...', duration: 3500 },
            { progress: 85, status: 'Reviewing security groups...', duration: 2500 },
            { progress: 95, status: 'Generating report...', duration: 2000 },
            { progress: 100, status: 'Scan completed!', duration: 1000 }
        ];
        
        let currentStep = 0;
        
        function executeStep() {
            if (currentStep >= scanSteps.length) {
                completeScan();
                return;
            }
            
            const step = scanSteps[currentStep];
            updateProgress(step.progress, step.status);
            

            if (step.progress > 30 && Math.random() > 0.7) {
                const mockFindings = [
                    {
                        type: 'S3_PUBLIC_ACCESS',
                        resource: 'my-bucket-' + Math.floor(Math.random() * 1000),
                        severity: 'HIGH',
                        description: 'S3 bucket is publicly accessible'
                    },
                    {
                        type: 'IAM_OVERPRIVILEGED',
                        resource: 'user-' + Math.floor(Math.random() * 100),
                        severity: 'MEDIUM',
                        description: 'IAM user has excessive permissions'
                    },
                    {
                        type: 'VPC_OPEN_SECURITY_GROUP',
                        resource: 'sg-' + Math.floor(Math.random() * 1000000),
                        severity: 'LOW',
                        description: 'Security group allows unrestricted access'
                    }
                ];
                
                const randomFinding = mockFindings[Math.floor(Math.random() * mockFindings.length)];
                addFinding(randomFinding);
            }
            
            currentStep++;
            setTimeout(executeStep, step.duration);
        }
        
        executeStep();
    }
    

    function completeScan() {
        clearInterval(scanInterval);
        

        if (scanResults) {
            scanResults.style.display = 'block';
            scanResults.classList.add('fade-in');
        }
        

        const totalDuration = document.getElementById('totalDuration');
        const totalFindings = document.getElementById('totalFindings');
        
        if (totalDuration) {
            const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
            const minutes = Math.floor(elapsed / 60);
            const seconds = elapsed % 60;
            totalDuration.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        }
        
        if (totalFindings) {
            totalFindings.textContent = findings.length;
        }
        

        if (startScanBtn) startScanBtn.style.display = 'inline-block';
        if (stopScanBtn) stopScanBtn.style.display = 'none';
        
        showAlert('Security scan completed successfully!', 'success');
    }
    

    function startScan() {
        const credentials = document.getElementById('credentials').value;
        const scanType = document.getElementById('scanType').value;
        const scanScope = Array.from(document.querySelectorAll('input[name="scope"]:checked')).map(cb => cb.value);
        const scanDepth = document.getElementById('scanDepth').value;
        
        if (!credentials || !scanType) {
            showAlert('Please fill in all required fields.', 'error');
            return;
        }
        

        findings = [];
        currentProgress = 0;
        scanStartTime = Date.now();
        

        if (scanProgress) scanProgress.style.display = 'block';
        if (findingsSection) findingsSection.style.display = 'block';
        if (scanResults) scanResults.style.display = 'none';
        

        const findingsList = document.getElementById('findingsList');
        if (findingsList) findingsList.innerHTML = '';
        

        if (startScanBtn) startScanBtn.style.display = 'none';
        if (stopScanBtn) stopScanBtn.style.display = 'inline-block';
        

        scanInterval = setInterval(updateElapsedTime, 1000);
        

        showAlert(`Starting ${scanType.toUpperCase()} security scan...`, 'info');
        

        startActualScan(credentials, scanScope, scanDepth);
    }
    

    function startActualScan(credentials, scanScope, scanDepth) {
        const scanData = {
            credentials: credentials,
            scope: scanScope,
            depth: scanDepth
        };
        
        fetch('/api/scan-aws', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(scanData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.session_id) {

                window.currentScanSession = data.session_id;
                

                if (data.findings && data.findings.length > 0) {
                    data.findings.forEach(finding => {
                        addFinding(finding);
                    });
                }
                

                completeScan();
                
                showAlert(`Scan completed! Found ${data.total_findings} issues.`, 'success');
            } else {
                throw new Error('Invalid response from server');
            }
        })
        .catch(error => {
            console.error('Scan error:', error);
            showAlert('Scan failed: ' + error.message, 'error');
            

            if (startScanBtn) startScanBtn.style.display = 'inline-block';
            if (stopScanBtn) stopScanBtn.style.display = 'none';
        });
    }
    

    function stopScan() {
        clearInterval(scanInterval);
        
        if (startScanBtn) startScanBtn.style.display = 'inline-block';
        if (stopScanBtn) stopScanBtn.style.display = 'none';
        
        showAlert('Scan stopped by user.', 'warning');
    }
    

    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            startScan();
        });
    }
    
    if (stopScanBtn) {
        stopScanBtn.addEventListener('click', stopScan);
    }
    

    const downloadReportBtn = document.getElementById('downloadReportBtn');
    if (downloadReportBtn) {
        downloadReportBtn.addEventListener('click', function() {
            const report = {
                timestamp: new Date().toISOString(),
                findings: findings,
                summary: {
                    total: findings.length,
                    high: findings.filter(f => f.severity === 'HIGH').length,
                    medium: findings.filter(f => f.severity === 'MEDIUM').length,
                    low: findings.filter(f => f.severity === 'LOW').length
                }
            };
            
            const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `security-scan-report-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            showAlert('Report downloaded successfully!', 'success');
        });
    }
    

    const viewDetailsBtn = document.getElementById('viewDetailsBtn');
    if (viewDetailsBtn) {
        viewDetailsBtn.addEventListener('click', function() {
            window.location.href = '/report';
        });
    }
    

    function updateConnectionStatus() {
        const statusElement = document.getElementById('connectionStatus');
        const indicator = document.querySelector('.status-indicator');
        
        if (statusElement && indicator) {

            const isConnected = Math.random() > 0.1; // 90% chance of being connected
            
            if (isConnected) {
                statusElement.textContent = 'Connected';
                indicator.className = 'status-indicator success';
            } else {
                statusElement.textContent = 'Disconnected';
                indicator.className = 'status-indicator error';
            }
        }
    }
    

    setInterval(updateConnectionStatus, 30000);
    updateConnectionStatus();
    

    const style = document.createElement('style');
    style.textContent = `
        .alert {
            position: relative;
            padding-right: 40px;
        }
        
        .alert-close {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: inherit;
            cursor: pointer;
            font-size: 1.2rem;
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .finding-time {
            font-size: 0.8rem;
            color: #666;
        }
        
        .navbar-right {
            display: flex;
            align-items: center;
            gap: 10px;
        }
    `;
    document.head.appendChild(style);
    
    console.log("Dynamic CloudSec UI loaded successfully!");
});
