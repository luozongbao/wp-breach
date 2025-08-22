/**
 * WP Breach Dashboard JavaScript
 *
 * Handles dashboard interactions, AJAX requests, charts,
 * and real-time updates for the admin interface.
 *
 * @package WP_Breach
 * @since 1.0.0
 */

(function($) {
    'use strict';

    /**
     * Dashboard Controller Class
     */
    class WPBreachDashboard {
        constructor() {
            this.scanInProgress = false;
            this.scanInterval = null;
            this.charts = {};
            
            this.init();
        }
        
        /**
         * Initialize dashboard
         */
        init() {
            this.bindEvents();
            this.initCharts();
            this.updateSecurityScore();
            this.checkScanStatus();
            
            // Auto-refresh dashboard data every 30 seconds
            setInterval(() => {
                if (!this.scanInProgress) {
                    this.refreshDashboardData();
                }
            }, 30000);
        }
        
        /**
         * Bind event handlers
         */
        bindEvents() {
            // Quick scan button
            $('#wp-breach-quick-scan, #wp-breach-first-scan, #wp-breach-action-scan').on('click', (e) => {
                e.preventDefault();
                this.startQuickScan();
            });
            
            // Full scan button
            $('#wp-breach-full-scan').on('click', (e) => {
                e.preventDefault();
                this.startFullScan();
            });
            
            // Refresh button
            $('#wp-breach-refresh-data').on('click', (e) => {
                e.preventDefault();
                this.refreshDashboardData();
            });
            
            // Vulnerability item clicks
            $('.wp-breach-vulnerability-item').on('click', (e) => {
                const vulnerabilityId = $(e.currentTarget).data('vulnerability-id');
                this.showVulnerabilityDetails(vulnerabilityId);
            });
            
            // View vulnerability buttons
            $('.wp-breach-view-vulnerability').on('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const vulnerabilityId = $(e.currentTarget).data('vulnerability-id');
                this.showVulnerabilityDetails(vulnerabilityId);
            });
            
            // Quick action buttons
            $('#wp-breach-action-vulnerabilities').on('click', () => {
                window.location.href = wpBreachDashboardData.adminUrl + 'admin.php?page=wp-breach-vulnerabilities';
            });
            
            $('#wp-breach-action-reports').on('click', () => {
                window.location.href = wpBreachDashboardData.adminUrl + 'admin.php?page=wp-breach-reports';
            });
            
            $('#wp-breach-action-settings').on('click', () => {
                window.location.href = wpBreachDashboardData.adminUrl + 'admin.php?page=wp-breach-settings';
            });
            
            // Modal controls
            $('.wp-breach-modal-close').on('click', () => {
                this.closeModal();
            });
            
            $('#wp-breach-pause-scan').on('click', () => {
                this.pauseScan();
            });
            
            $('#wp-breach-cancel-scan').on('click', () => {
                this.cancelScan();
            });
            
            // Close modal on backdrop click
            $('.wp-breach-modal').on('click', (e) => {
                if (e.target === e.currentTarget) {
                    this.closeModal();
                }
            });
            
            // Keyboard navigation
            $(document).on('keydown', (e) => {
                if (e.key === 'Escape') {
                    this.closeModal();
                }
            });
        }
        
        /**
         * Initialize charts
         */
        initCharts() {
            this.initScanTrendChart();
            this.initVulnerabilityDistributionChart();
        }
        
        /**
         * Initialize scan trend chart
         */
        initScanTrendChart() {
            const canvas = document.getElementById('wp-breach-scan-chart');
            if (!canvas) return;
            
            const ctx = canvas.getContext('2d');
            const scanHistory = wpBreachDashboardData.scanHistory || [];
            
            // Prepare data
            const labels = scanHistory.map(item => {
                const date = new Date(item.scan_date);
                return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            });
            
            const scanCounts = scanHistory.map(item => parseInt(item.scan_count) || 0);
            const issueCounts = scanHistory.map(item => parseInt(item.issues_found) || 0);
            
            // Create chart (using basic canvas drawing since Chart.js might not be available)
            this.drawLineChart(ctx, {
                labels: labels,
                datasets: [
                    { label: 'Scans', data: scanCounts, color: '#0073aa' },
                    { label: 'Issues', data: issueCounts, color: '#dc3232' }
                ]
            });
        }
        
        /**
         * Initialize vulnerability distribution chart
         */
        initVulnerabilityDistributionChart() {
            const canvas = document.getElementById('wp-breach-distribution-chart');
            if (!canvas) return;
            
            const ctx = canvas.getContext('2d');
            const distribution = wpBreachDashboardData.vulnerabilityDistribution || [];
            
            // Prepare data
            const data = distribution.map(item => ({
                label: item.type,
                value: parseInt(item.count) || 0,
                color: this.getVulnerabilityTypeColor(item.type)
            }));
            
            // Create pie chart
            this.drawPieChart(ctx, data);
        }
        
        /**
         * Draw simple line chart
         */
        drawLineChart(ctx, data) {
            const canvas = ctx.canvas;
            const width = canvas.width;
            const height = canvas.height;
            const padding = 40;
            
            // Clear canvas
            ctx.clearRect(0, 0, width, height);
            
            if (!data.labels.length) {
                ctx.fillStyle = '#666';
                ctx.font = '14px sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText('No data available', width / 2, height / 2);
                return;
            }
            
            // Calculate scales
            const chartWidth = width - padding * 2;
            const chartHeight = height - padding * 2;
            
            const maxValue = Math.max(
                ...data.datasets.map(dataset => Math.max(...dataset.data))
            ) || 1;
            
            const xStep = chartWidth / (data.labels.length - 1 || 1);
            const yStep = chartHeight / maxValue;
            
            // Draw grid
            ctx.strokeStyle = '#e1e1e1';
            ctx.lineWidth = 1;
            
            // Vertical grid lines
            for (let i = 0; i < data.labels.length; i++) {
                const x = padding + i * xStep;
                ctx.beginPath();
                ctx.moveTo(x, padding);
                ctx.lineTo(x, height - padding);
                ctx.stroke();
            }
            
            // Horizontal grid lines
            for (let i = 0; i <= 5; i++) {
                const y = padding + (chartHeight / 5) * i;
                ctx.beginPath();
                ctx.moveTo(padding, y);
                ctx.lineTo(width - padding, y);
                ctx.stroke();
            }
            
            // Draw datasets
            data.datasets.forEach(dataset => {
                ctx.strokeStyle = dataset.color;
                ctx.fillStyle = dataset.color;
                ctx.lineWidth = 2;
                
                // Draw line
                ctx.beginPath();
                dataset.data.forEach((value, index) => {
                    const x = padding + index * xStep;
                    const y = height - padding - value * yStep;
                    
                    if (index === 0) {
                        ctx.moveTo(x, y);
                    } else {
                        ctx.lineTo(x, y);
                    }
                });
                ctx.stroke();
                
                // Draw points
                dataset.data.forEach((value, index) => {
                    const x = padding + index * xStep;
                    const y = height - padding - value * yStep;
                    
                    ctx.beginPath();
                    ctx.arc(x, y, 3, 0, 2 * Math.PI);
                    ctx.fill();
                });
            });
            
            // Draw labels
            ctx.fillStyle = '#333';
            ctx.font = '12px sans-serif';
            ctx.textAlign = 'center';
            
            data.labels.forEach((label, index) => {
                const x = padding + index * xStep;
                ctx.fillText(label, x, height - 10);
            });
        }
        
        /**
         * Draw simple pie chart
         */
        drawPieChart(ctx, data) {
            const canvas = ctx.canvas;
            const centerX = canvas.width / 2;
            const centerY = canvas.height / 2;
            const radius = Math.min(canvas.width, canvas.height) / 2 - 20;
            
            // Clear canvas
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            if (!data.length) {
                ctx.fillStyle = '#666';
                ctx.font = '14px sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText('No data available', centerX, centerY);
                return;
            }
            
            const total = data.reduce((sum, item) => sum + item.value, 0);
            let currentAngle = -Math.PI / 2; // Start at top
            
            data.forEach(item => {
                const sliceAngle = (item.value / total) * 2 * Math.PI;
                
                // Draw slice
                ctx.beginPath();
                ctx.moveTo(centerX, centerY);
                ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + sliceAngle);
                ctx.closePath();
                ctx.fillStyle = item.color;
                ctx.fill();
                
                // Draw slice border
                ctx.strokeStyle = '#fff';
                ctx.lineWidth = 2;
                ctx.stroke();
                
                currentAngle += sliceAngle;
            });
        }
        
        /**
         * Get color for vulnerability type
         */
        getVulnerabilityTypeColor(type) {
            const colors = {
                'sql_injection': '#dc3232',
                'xss': '#ffb900',
                'file_inclusion': '#0073aa',
                'weak_password': '#46b450',
                'outdated_plugin': '#9b59b6',
                'outdated_theme': '#e67e22',
                'permission_issue': '#f39c12',
                'default': '#666'
            };
            
            return colors[type] || colors.default;
        }
        
        /**
         * Update security score display
         */
        updateSecurityScore() {
            const score = wpBreachDashboardData.securityScore || 0;
            const scoreCircle = $('.wp-breach-score-circle');
            
            if (scoreCircle.length) {
                scoreCircle.css('--score', score);
                
                // Update score color based on value
                let scoreClass = 'wp-breach-score-good';
                if (score < 60) {
                    scoreClass = 'wp-breach-score-poor';
                } else if (score < 80) {
                    scoreClass = 'wp-breach-score-fair';
                }
                
                $('.wp-breach-score-description span').removeClass('wp-breach-score-good wp-breach-score-fair wp-breach-score-poor').addClass(scoreClass);
            }
        }
        
        /**
         * Start quick scan
         */
        startQuickScan() {
            this.startScan({
                type: 'quick',
                targets: ['core', 'plugins', 'themes'],
                depth: 'basic'
            });
        }
        
        /**
         * Start full scan
         */
        startFullScan() {
            this.startScan({
                type: 'full',
                targets: ['core', 'plugins', 'themes', 'uploads', 'database'],
                depth: 'deep'
            });
        }
        
        /**
         * Start security scan
         */
        startScan(config = {}) {
            if (this.scanInProgress) {
                this.showNotice('error', 'A scan is already in progress.');
                return;
            }
            
            this.showScanModal();
            this.scanInProgress = true;
            
            // Update UI
            this.updateScanProgress(0, 'Initializing scan...');
            
            // Start scan via AJAX
            $.ajax({
                url: wpBreachDashboardData.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'wp_breach_start_scan',
                    nonce: wpBreachDashboardData.nonce,
                    config: JSON.stringify(config)
                },
                success: (response) => {
                    if (response.success) {
                        this.monitorScanProgress(response.data.scan_id);
                    } else {
                        this.handleScanError(response.data);
                    }
                },
                error: () => {
                    this.handleScanError('Failed to start scan. Please try again.');
                }
            });
        }
        
        /**
         * Monitor scan progress
         */
        monitorScanProgress(scanId) {
            this.scanInterval = setInterval(() => {
                $.ajax({
                    url: wpBreachDashboardData.ajaxUrl,
                    type: 'POST',
                    data: {
                        action: 'wp_breach_scan_progress',
                        nonce: wpBreachDashboardData.nonce,
                        scan_id: scanId
                    },
                    success: (response) => {
                        if (response.success) {
                            const progress = response.data;
                            this.updateScanProgress(
                                progress.percentage || 0,
                                progress.current_phase || 'Processing...',
                                progress.items_scanned || 0,
                                progress.issues_found || 0
                            );
                            
                            // Check if scan is complete
                            if (progress.status === 'completed' || progress.status === 'failed') {
                                this.handleScanComplete(progress);
                            }
                        }
                    },
                    error: () => {
                        this.handleScanError('Lost connection to scan process.');
                    }
                });
            }, 2000);
        }
        
        /**
         * Update scan progress display
         */
        updateScanProgress(percentage, status, itemsScanned = 0, issuesFound = 0) {
            $('.wp-breach-progress-fill').css('width', percentage + '%');
            $('.wp-breach-progress-percentage').text(Math.round(percentage) + '%');
            $('.wp-breach-progress-status').text(status);
            $('#wp-breach-scan-phase').text(status);
            $('#wp-breach-scan-items').text(itemsScanned);
            $('#wp-breach-scan-issues').text(issuesFound);
        }
        
        /**
         * Handle scan completion
         */
        handleScanComplete(progress) {
            clearInterval(this.scanInterval);
            this.scanInProgress = false;
            
            setTimeout(() => {
                this.closeModal();
                
                if (progress.status === 'completed') {
                    this.showNotice('success', 'Security scan completed successfully!');
                    this.refreshDashboardData();
                } else {
                    this.showNotice('error', 'Scan failed: ' + (progress.error || 'Unknown error'));
                }
            }, 2000);
        }
        
        /**
         * Handle scan error
         */
        handleScanError(error) {
            clearInterval(this.scanInterval);
            this.scanInProgress = false;
            this.closeModal();
            
            const message = typeof error === 'string' ? error : 'An error occurred during the scan.';
            this.showNotice('error', message);
        }
        
        /**
         * Pause current scan
         */
        pauseScan() {
            $.ajax({
                url: wpBreachDashboardData.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'wp_breach_pause_scan',
                    nonce: wpBreachDashboardData.nonce
                },
                success: (response) => {
                    if (response.success) {
                        $('#wp-breach-pause-scan').text('Resume').off('click').on('click', () => this.resumeScan());
                        this.showNotice('info', 'Scan paused.');
                    }
                }
            });
        }
        
        /**
         * Resume paused scan
         */
        resumeScan() {
            $.ajax({
                url: wpBreachDashboardData.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'wp_breach_resume_scan',
                    nonce: wpBreachDashboardData.nonce
                },
                success: (response) => {
                    if (response.success) {
                        $('#wp-breach-pause-scan').text('Pause').off('click').on('click', () => this.pauseScan());
                        this.showNotice('info', 'Scan resumed.');
                    }
                }
            });
        }
        
        /**
         * Cancel current scan
         */
        cancelScan() {
            $.ajax({
                url: wpBreachDashboardData.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'wp_breach_cancel_scan',
                    nonce: wpBreachDashboardData.nonce
                },
                success: (response) => {
                    clearInterval(this.scanInterval);
                    this.scanInProgress = false;
                    this.closeModal();
                    this.showNotice('info', 'Scan cancelled.');
                }
            });
        }
        
        /**
         * Show scan modal
         */
        showScanModal() {
            $('#wp-breach-scan-modal').fadeIn(300);
            $('body').addClass('modal-open');
        }
        
        /**
         * Close modal
         */
        closeModal() {
            $('.wp-breach-modal').fadeOut(300);
            $('body').removeClass('modal-open');
        }
        
        /**
         * Show vulnerability details
         */
        showVulnerabilityDetails(vulnerabilityId) {
            // This would open a detailed modal - for now, redirect to vulnerabilities page
            window.location.href = wpBreachDashboardData.adminUrl + 
                'admin.php?page=wp-breach-vulnerabilities&vulnerability=' + vulnerabilityId;
        }
        
        /**
         * Refresh dashboard data
         */
        refreshDashboardData() {
            $('.wp-breach-dashboard').addClass('wp-breach-loading');
            
            $.ajax({
                url: wpBreachDashboardData.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'wp_breach_refresh_dashboard',
                    nonce: wpBreachDashboardData.nonce
                },
                success: (response) => {
                    if (response.success) {
                        // Update dashboard data
                        wpBreachDashboardData = Object.assign(wpBreachDashboardData, response.data);
                        
                        // Refresh UI components
                        this.updateDashboardCards(response.data);
                        this.updateVulnerabilityList(response.data.recent_vulnerabilities);
                        this.updateLatestScan(response.data.last_scan);
                        this.updateSystemInfo(response.data.system_status);
                        
                        // Refresh charts
                        this.initCharts();
                        this.updateSecurityScore();
                        
                        this.showNotice('success', 'Dashboard refreshed successfully.');
                    } else {
                        this.showNotice('error', 'Failed to refresh dashboard data.');
                    }
                },
                error: () => {
                    this.showNotice('error', 'Failed to refresh dashboard data.');
                },
                complete: () => {
                    $('.wp-breach-dashboard').removeClass('wp-breach-loading');
                }
            });
        }
        
        /**
         * Update dashboard cards
         */
        updateDashboardCards(data) {
            if (data.security_status) {
                $('.wp-breach-card-critical .wp-breach-card-number').text(data.security_status.critical);
                $('.wp-breach-card-high .wp-breach-card-number').text(data.security_status.high);
                $('.wp-breach-card-medium .wp-breach-card-number').text(data.security_status.medium);
                $('.wp-breach-card-low .wp-breach-card-number').text(data.security_status.low);
            }
            
            if (data.security_score !== undefined) {
                $('.wp-breach-score-number').text(data.security_score);
            }
        }
        
        /**
         * Update vulnerability list
         */
        updateVulnerabilityList(vulnerabilities) {
            const container = $('.wp-breach-vulnerability-list');
            if (!container.length) return;
            
            if (!vulnerabilities || !vulnerabilities.length) {
                container.html('<div class="wp-breach-no-vulnerabilities"><p>No vulnerabilities found. Your site appears secure!</p></div>');
                return;
            }
            
            let html = '';
            vulnerabilities.forEach(vuln => {
                html += `
                    <div class="wp-breach-vulnerability-item" data-vulnerability-id="${vuln.id}">
                        <div class="wp-breach-vulnerability-severity wp-breach-severity-${vuln.severity}">
                            ${vuln.severity.charAt(0).toUpperCase() + vuln.severity.slice(1)}
                        </div>
                        <div class="wp-breach-vulnerability-details">
                            <div class="wp-breach-vulnerability-title">
                                <strong>${vuln.title}</strong>
                            </div>
                            <div class="wp-breach-vulnerability-meta">
                                <span class="wp-breach-vulnerability-type">${vuln.type}</span>
                                <span class="wp-breach-vulnerability-time">${vuln.time_ago} ago</span>
                            </div>
                        </div>
                        <div class="wp-breach-vulnerability-actions">
                            <button type="button" class="button button-small wp-breach-view-vulnerability" data-vulnerability-id="${vuln.id}">
                                View
                            </button>
                        </div>
                    </div>
                `;
            });
            
            container.html(html);
            
            // Re-bind events for new elements
            container.find('.wp-breach-vulnerability-item').on('click', (e) => {
                const vulnerabilityId = $(e.currentTarget).data('vulnerability-id');
                this.showVulnerabilityDetails(vulnerabilityId);
            });
        }
        
        /**
         * Update latest scan information
         */
        updateLatestScan(scanData) {
            const container = $('.wp-breach-latest-scan .wp-breach-widget-content');
            
            if (!scanData) {
                container.html(`
                    <div class="wp-breach-no-scan">
                        <p>No scans have been run yet.</p>
                        <button type="button" class="button button-primary" id="wp-breach-first-scan">
                            Run Your First Scan
                        </button>
                    </div>
                `);
                return;
            }
            
            container.html(`
                <div class="wp-breach-scan-summary">
                    <div class="wp-breach-scan-info">
                        <strong>Status:</strong>
                        <span class="wp-breach-status wp-breach-status-${scanData.status}">
                            ${scanData.status.charAt(0).toUpperCase() + scanData.status.slice(1)}
                        </span>
                    </div>
                    <div class="wp-breach-scan-info">
                        <strong>Completed:</strong>
                        <span>${scanData.time_ago} ago</span>
                    </div>
                    <div class="wp-breach-scan-info">
                        <strong>Duration:</strong>
                        <span>${scanData.duration || 'N/A'}</span>
                    </div>
                    <div class="wp-breach-scan-info">
                        <strong>Items Scanned:</strong>
                        <span>${scanData.items_scanned || 0}</span>
                    </div>
                </div>
            `);
        }
        
        /**
         * Update system information
         */
        updateSystemInfo(systemStatus) {
            if (!systemStatus) return;
            
            $('.wp-breach-system-stats').html(`
                <div class="wp-breach-system-stat">
                    <span class="wp-breach-stat-label">WordPress Version:</span>
                    <span class="wp-breach-stat-value">${systemStatus.wordpress_version}</span>
                </div>
                <div class="wp-breach-system-stat">
                    <span class="wp-breach-stat-label">PHP Version:</span>
                    <span class="wp-breach-stat-value">${systemStatus.php_version}</span>
                </div>
                <div class="wp-breach-system-stat">
                    <span class="wp-breach-stat-label">Memory Usage:</span>
                    <span class="wp-breach-stat-value">${systemStatus.memory_usage}</span>
                </div>
                <div class="wp-breach-system-stat">
                    <span class="wp-breach-stat-label">Active Plugins:</span>
                    <span class="wp-breach-stat-value">${systemStatus.active_plugins}</span>
                </div>
                <div class="wp-breach-system-stat">
                    <span class="wp-breach-stat-label">SSL Enabled:</span>
                    <span class="wp-breach-stat-value">${systemStatus.ssl_enabled ? 'Yes' : 'No'}</span>
                </div>
            `);
        }
        
        /**
         * Check current scan status on page load
         */
        checkScanStatus() {
            $.ajax({
                url: wpBreachDashboardData.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'wp_breach_scan_status',
                    nonce: wpBreachDashboardData.nonce
                },
                success: (response) => {
                    if (response.success && response.data.status === 'running') {
                        this.scanInProgress = true;
                        this.showScanModal();
                        this.monitorScanProgress(response.data.scan_id);
                    }
                }
            });
        }
        
        /**
         * Show notification
         */
        showNotice(type, message) {
            const notice = $(`
                <div class="notice notice-${type} is-dismissible wp-breach-notice">
                    <p>${message}</p>
                    <button type="button" class="notice-dismiss">
                        <span class="screen-reader-text">Dismiss this notice.</span>
                    </button>
                </div>
            `);
            
            $('.wrap').after(notice);
            
            // Auto-dismiss after 5 seconds
            setTimeout(() => {
                notice.fadeOut(() => notice.remove());
            }, 5000);
            
            // Handle dismiss button
            notice.find('.notice-dismiss').on('click', () => {
                notice.fadeOut(() => notice.remove());
            });
        }
    }

    /**
     * Initialize dashboard when DOM is ready
     */
    $(document).ready(() => {
        if ($('.wp-breach-dashboard').length) {
            new WPBreachDashboard();
        }
    });

})(jQuery);
