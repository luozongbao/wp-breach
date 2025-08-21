/**
 * All of the JavaScript for your admin-facing functionality should be
 * included in this file.
 */

(function( $ ) {
    'use strict';

    // Main WP-Breach Admin Object
    var WPBreachAdmin = {
        
        /**
         * Initialize the admin functionality
         */
        init: function() {
            this.bindEvents();
            this.initDashboard();
            this.initVulnerabilityScanner();
            this.initQuickFix();
            this.initMonitoring();
            this.initSettings();
        },

        /**
         * Bind event handlers
         */
        bindEvents: function() {
            // Quick scan button
            $(document).on('click', '.wp-breach-quick-scan', this.runQuickScan);
            
            // Vulnerability actions
            $(document).on('click', '.wp-breach-fix-vulnerability', this.fixVulnerability);
            $(document).on('click', '.wp-breach-dismiss-vulnerability', this.dismissVulnerability);
            
            // Settings form
            $(document).on('submit', '.wp-breach-settings-form', this.saveSettings);
            
            // Report generation
            $(document).on('click', '.wp-breach-generate-report', this.generateReport);
            
            // Tab navigation
            $(document).on('click', '.wp-breach-tab', this.switchTab);
            
            // Accordion toggles
            $(document).on('click', '.wp-breach-accordion-toggle', this.toggleAccordion);
        },

        /**
         * Initialize dashboard functionality
         */
        initDashboard: function() {
            // Auto-refresh dashboard data every 30 seconds
            if ($('.wp-breach-dashboard').length) {
                setInterval(this.refreshDashboard, 30000);
                
                // Initialize charts if present
                this.initCharts();
            }
        },

        /**
         * Initialize vulnerability scanner
         */
        initVulnerabilityScanner: function() {
            // Check for ongoing scans
            this.checkScanStatus();
            
            // Initialize real-time scan updates
            if ($('.wp-breach-scan-progress').length) {
                this.initScanProgress();
            }
        },

        /**
         * Initialize quick fix functionality
         */
        initQuickFix: function() {
            // Auto-apply fixes toggle
            $(document).on('change', '.wp-breach-auto-fix-toggle', function() {
                var enabled = $(this).is(':checked');
                WPBreachAdmin.toggleAutoFix(enabled);
            });
        },

        /**
         * Initialize monitoring features
         */
        initMonitoring: function() {
            // Real-time monitoring updates
            if ($('.wp-breach-monitoring').length) {
                this.initRealTimeMonitoring();
            }
        },

        /**
         * Initialize settings page
         */
        initSettings: function() {
            // Setting dependencies
            $(document).on('change', '.wp-breach-setting-toggle', this.handleSettingDependencies);
            
            // Validate settings
            $(document).on('blur', '.wp-breach-setting-input', this.validateSetting);
        },

        /**
         * Run quick scan
         */
        runQuickScan: function(e) {
            e.preventDefault();
            
            var $button = $(this);
            var originalText = $button.text();
            
            // Disable button and show loading
            $button.prop('disabled', true).html('<span class="wp-breach-spinner"></span> Scanning...');
            
            $.ajax({
                url: wp_breach_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'wp_breach_quick_scan',
                    nonce: wp_breach_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        WPBreachAdmin.showNotice('Scan completed successfully', 'success');
                        WPBreachAdmin.refreshDashboard();
                    } else {
                        WPBreachAdmin.showNotice(response.data.message || 'Scan failed', 'error');
                    }
                },
                error: function() {
                    WPBreachAdmin.showNotice('Failed to start scan', 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        },

        /**
         * Fix vulnerability
         */
        fixVulnerability: function(e) {
            e.preventDefault();
            
            var $button = $(this);
            var vulnerabilityId = $button.data('vulnerability-id');
            var originalText = $button.text();
            
            if (!confirm('Are you sure you want to apply this fix? This action cannot be undone.')) {
                return;
            }
            
            $button.prop('disabled', true).html('<span class="wp-breach-spinner"></span> Fixing...');
            
            $.ajax({
                url: wp_breach_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'wp_breach_fix_vulnerability',
                    vulnerability_id: vulnerabilityId,
                    nonce: wp_breach_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        WPBreachAdmin.showNotice('Vulnerability fixed successfully', 'success');
                        $button.closest('.wp-breach-vulnerability-item').fadeOut();
                    } else {
                        WPBreachAdmin.showNotice(response.data.message || 'Fix failed', 'error');
                    }
                },
                error: function() {
                    WPBreachAdmin.showNotice('Failed to apply fix', 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        },

        /**
         * Dismiss vulnerability
         */
        dismissVulnerability: function(e) {
            e.preventDefault();
            
            var $button = $(this);
            var vulnerabilityId = $button.data('vulnerability-id');
            
            if (!confirm('Are you sure you want to dismiss this vulnerability?')) {
                return;
            }
            
            $.ajax({
                url: wp_breach_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'wp_breach_dismiss_vulnerability',
                    vulnerability_id: vulnerabilityId,
                    nonce: wp_breach_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        WPBreachAdmin.showNotice('Vulnerability dismissed', 'success');
                        $button.closest('.wp-breach-vulnerability-item').fadeOut();
                    } else {
                        WPBreachAdmin.showNotice(response.data.message || 'Dismiss failed', 'error');
                    }
                },
                error: function() {
                    WPBreachAdmin.showNotice('Failed to dismiss vulnerability', 'error');
                }
            });
        },

        /**
         * Save settings
         */
        saveSettings: function(e) {
            e.preventDefault();
            
            var $form = $(this);
            var $submitButton = $form.find('input[type="submit"]');
            var originalText = $submitButton.val();
            
            $submitButton.prop('disabled', true).val('Saving...');
            
            $.ajax({
                url: wp_breach_ajax.ajax_url,
                type: 'POST',
                data: $form.serialize() + '&action=wp_breach_save_settings&nonce=' + wp_breach_ajax.nonce,
                success: function(response) {
                    if (response.success) {
                        WPBreachAdmin.showNotice('Settings saved successfully', 'success');
                    } else {
                        WPBreachAdmin.showNotice(response.data.message || 'Failed to save settings', 'error');
                    }
                },
                error: function() {
                    WPBreachAdmin.showNotice('Failed to save settings', 'error');
                },
                complete: function() {
                    $submitButton.prop('disabled', false).val(originalText);
                }
            });
        },

        /**
         * Generate report
         */
        generateReport: function(e) {
            e.preventDefault();
            
            var $button = $(this);
            var reportType = $button.data('report-type');
            var originalText = $button.text();
            
            $button.prop('disabled', true).html('<span class="wp-breach-spinner"></span> Generating...');
            
            $.ajax({
                url: wp_breach_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'wp_breach_generate_report',
                    report_type: reportType,
                    nonce: wp_breach_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        // Download the report
                        window.location = response.data.download_url;
                        WPBreachAdmin.showNotice('Report generated successfully', 'success');
                    } else {
                        WPBreachAdmin.showNotice(response.data.message || 'Report generation failed', 'error');
                    }
                },
                error: function() {
                    WPBreachAdmin.showNotice('Failed to generate report', 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        },

        /**
         * Switch tabs
         */
        switchTab: function(e) {
            e.preventDefault();
            
            var $tab = $(this);
            var target = $tab.data('target');
            
            // Remove active class from all tabs and content
            $('.wp-breach-tab').removeClass('active');
            $('.wp-breach-tab-content').removeClass('active');
            
            // Add active class to clicked tab and target content
            $tab.addClass('active');
            $(target).addClass('active');
        },

        /**
         * Toggle accordion
         */
        toggleAccordion: function(e) {
            e.preventDefault();
            
            var $toggle = $(this);
            var $content = $toggle.next('.wp-breach-accordion-content');
            
            $toggle.toggleClass('active');
            $content.slideToggle();
        },

        /**
         * Check scan status
         */
        checkScanStatus: function() {
            $.ajax({
                url: wp_breach_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'wp_breach_get_scan_status',
                    nonce: wp_breach_ajax.nonce
                },
                success: function(response) {
                    if (response.success && response.data.status === 'running') {
                        // Scan is running, continue checking
                        setTimeout(WPBreachAdmin.checkScanStatus, 5000);
                    }
                }
            });
        },

        /**
         * Initialize scan progress updates
         */
        initScanProgress: function() {
            var updateProgress = function() {
                $.ajax({
                    url: wp_breach_ajax.ajax_url,
                    type: 'POST',
                    data: {
                        action: 'wp_breach_get_scan_progress',
                        nonce: wp_breach_ajax.nonce
                    },
                    success: function(response) {
                        if (response.success) {
                            var progress = response.data.progress;
                            $('.wp-breach-progress-bar').css('width', progress + '%');
                            $('.wp-breach-progress-text').text(progress + '%');
                            
                            if (progress < 100) {
                                setTimeout(updateProgress, 1000);
                            }
                        }
                    }
                });
            };
            
            updateProgress();
        },

        /**
         * Initialize real-time monitoring
         */
        initRealTimeMonitoring: function() {
            setInterval(function() {
                $.ajax({
                    url: wp_breach_ajax.ajax_url,
                    type: 'POST',
                    data: {
                        action: 'wp_breach_get_monitoring_data',
                        nonce: wp_breach_ajax.nonce
                    },
                    success: function(response) {
                        if (response.success) {
                            WPBreachAdmin.updateMonitoringDisplay(response.data);
                        }
                    }
                });
            }, 10000); // Update every 10 seconds
        },

        /**
         * Initialize charts
         */
        initCharts: function() {
            // This would integrate with Chart.js or similar library
            if (typeof Chart !== 'undefined') {
                // Initialize vulnerability trend chart
                var ctx = document.getElementById('wp-breach-vulnerability-chart');
                if (ctx) {
                    new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                            datasets: [{
                                label: 'Vulnerabilities Found',
                                data: [12, 19, 3, 5, 2, 3],
                                borderColor: '#dc3232',
                                backgroundColor: 'rgba(220, 50, 50, 0.1)'
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false
                        }
                    });
                }
            }
        },

        /**
         * Refresh dashboard data
         */
        refreshDashboard: function() {
            $.ajax({
                url: wp_breach_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'wp_breach_refresh_dashboard',
                    nonce: wp_breach_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        // Update dashboard statistics
                        $('.wp-breach-stat-number').each(function() {
                            var $stat = $(this);
                            var statType = $stat.data('stat-type');
                            if (response.data.stats[statType]) {
                                $stat.text(response.data.stats[statType]);
                            }
                        });
                    }
                }
            });
        },

        /**
         * Show admin notice
         */
        showNotice: function(message, type) {
            type = type || 'info';
            
            var $notice = $('<div class="wp-breach-notice ' + type + '">' + message + '</div>');
            
            // Remove existing notices
            $('.wp-breach-notice').remove();
            
            // Add new notice
            $('.wp-breach-admin-content').prepend($notice);
            
            // Auto-hide after 5 seconds
            setTimeout(function() {
                $notice.fadeOut(function() {
                    $(this).remove();
                });
            }, 5000);
        },

        /**
         * Handle setting dependencies
         */
        handleSettingDependencies: function() {
            var $toggle = $(this);
            var dependentFields = $toggle.data('dependent-fields');
            
            if (dependentFields) {
                var fields = dependentFields.split(',');
                var isChecked = $toggle.is(':checked');
                
                fields.forEach(function(field) {
                    var $field = $('#' + field.trim());
                    $field.prop('disabled', !isChecked);
                    $field.closest('.wp-breach-form-row').toggle(isChecked);
                });
            }
        },

        /**
         * Validate setting
         */
        validateSetting: function() {
            var $input = $(this);
            var validationType = $input.data('validation');
            var value = $input.val();
            var isValid = true;
            
            switch (validationType) {
                case 'email':
                    isValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
                    break;
                case 'url':
                    isValid = /^https?:\/\/.+$/.test(value);
                    break;
                case 'number':
                    isValid = !isNaN(value) && value >= 0;
                    break;
            }
            
            if (isValid) {
                $input.removeClass('invalid');
            } else {
                $input.addClass('invalid');
            }
        },

        /**
         * Toggle auto-fix functionality
         */
        toggleAutoFix: function(enabled) {
            $.ajax({
                url: wp_breach_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'wp_breach_toggle_auto_fix',
                    enabled: enabled ? 1 : 0,
                    nonce: wp_breach_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        var message = enabled ? 'Auto-fix enabled' : 'Auto-fix disabled';
                        WPBreachAdmin.showNotice(message, 'success');
                    } else {
                        WPBreachAdmin.showNotice('Failed to update auto-fix setting', 'error');
                    }
                }
            });
        },

        /**
         * Update monitoring display
         */
        updateMonitoringDisplay: function(data) {
            // Update threat level indicator
            if (data.threat_level) {
                $('.wp-breach-threat-level')
                    .removeClass('secure warning critical')
                    .addClass(data.threat_level)
                    .text(data.threat_level.toUpperCase());
            }
            
            // Update active threats count
            if (data.active_threats !== undefined) {
                $('.wp-breach-active-threats').text(data.active_threats);
            }
            
            // Update last scan time
            if (data.last_scan) {
                $('.wp-breach-last-scan').text(data.last_scan);
            }
        }
    };

    // Initialize when document is ready
    $(document).ready(function() {
        WPBreachAdmin.init();
    });

})( jQuery );
