/**
 * All of the JavaScript for your public-facing functionality should be
 * included in this file.
 */

(function( $ ) {
    'use strict';

    // Main WP-Breach Public Object
    var WPBreachPublic = {
        
        /**
         * Initialize the public functionality
         */
        init: function() {
            this.bindEvents();
            this.initSecurityWidget();
            this.initReportForm();
            this.initSecurityMonitoring();
        },

        /**
         * Bind event handlers
         */
        bindEvents: function() {
            // Security report form submission
            $(document).on('submit', '.wp-breach-report-form', this.submitSecurityReport);
            
            // Security status refresh
            $(document).on('click', '.wp-breach-refresh-status', this.refreshSecurityStatus);
            
            // Security tips toggle
            $(document).on('click', '.wp-breach-tips-toggle', this.toggleSecurityTips);
        },

        /**
         * Initialize security widget
         */
        initSecurityWidget: function() {
            // Auto-refresh security status every 60 seconds
            if ($('.wp-breach-security-widget').length) {
                setInterval(this.refreshSecurityStatus, 60000);
            }
            
            // Initialize status animations
            this.animateStatusChange();
        },

        /**
         * Initialize report form
         */
        initReportForm: function() {
            // Form validation
            $(document).on('blur', '.wp-breach-report-form input, .wp-breach-report-form textarea', this.validateField);
            
            // Character counter for textarea
            $(document).on('input', '.wp-breach-report-form textarea', this.updateCharacterCount);
            
            // Auto-fill current URL
            this.autoFillCurrentURL();
        },

        /**
         * Initialize security monitoring
         */
        initSecurityMonitoring: function() {
            // Monitor for suspicious activity
            this.monitorUserActivity();
            
            // Check for security headers
            this.checkSecurityHeaders();
        },

        /**
         * Submit security report
         */
        submitSecurityReport: function(e) {
            e.preventDefault();
            
            var $form = $(this);
            var $submitButton = $form.find('.wp-breach-submit-button');
            var originalText = $submitButton.text();
            
            // Validate form
            if (!WPBreachPublic.validateReportForm($form)) {
                return;
            }
            
            // Show loading state
            $submitButton.prop('disabled', true).html('<span class="wp-breach-loading"></span> Submitting...');
            
            // Collect form data
            var formData = {
                action: 'wp_breach_report_security_issue',
                nonce: wp_breach_public_ajax.nonce,
                issue_description: $form.find('[name="issue_description"]').val(),
                issue_url: $form.find('[name="issue_url"]').val(),
                reporter_email: $form.find('[name="reporter_email"]').val(),
                issue_severity: $form.find('[name="issue_severity"]').val()
            };
            
            $.ajax({
                url: wp_breach_public_ajax.ajax_url,
                type: 'POST',
                data: formData,
                success: function(response) {
                    if (response.success) {
                        WPBreachPublic.showAlert('Thank you for reporting the security issue. We will investigate it promptly.', 'success');
                        $form[0].reset();
                    } else {
                        WPBreachPublic.showAlert(response.data.message || 'Failed to submit report. Please try again.', 'error');
                    }
                },
                error: function() {
                    WPBreachPublic.showAlert('Network error. Please check your connection and try again.', 'error');
                },
                complete: function() {
                    $submitButton.prop('disabled', false).text(originalText);
                }
            });
        },

        /**
         * Refresh security status
         */
        refreshSecurityStatus: function() {
            var $widget = $('.wp-breach-security-widget');
            var $statusIndicator = $widget.find('.wp-breach-security-status');
            
            if (!$widget.length) return;
            
            // Add loading indicator
            $statusIndicator.addClass('loading');
            
            $.ajax({
                url: wp_breach_public_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'wp_breach_get_public_security_status',
                    nonce: wp_breach_public_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        WPBreachPublic.updateSecurityStatus(response.data);
                    }
                },
                complete: function() {
                    $statusIndicator.removeClass('loading');
                }
            });
        },

        /**
         * Update security status display
         */
        updateSecurityStatus: function(data) {
            var $widget = $('.wp-breach-security-widget');
            var $statusIcon = $widget.find('.wp-breach-status-icon');
            var $statusText = $widget.find('.wp-breach-status-text');
            
            // Update status icon
            $statusIcon.removeClass('secure warning critical').addClass(data.status);
            
            // Update status text
            $statusText.text(data.message);
            
            // Animate change
            $widget.addClass('wp-breach-status-change');
            setTimeout(function() {
                $widget.removeClass('wp-breach-status-change');
            }, 500);
            
            // Update last check time
            var now = new Date();
            $widget.find('.wp-breach-last-check').text('Last checked: ' + now.toLocaleTimeString());
        },

        /**
         * Validate report form
         */
        validateReportForm: function($form) {
            var isValid = true;
            var $requiredFields = $form.find('[required]');
            
            $requiredFields.each(function() {
                var $field = $(this);
                if (!$field.val().trim()) {
                    WPBreachPublic.showFieldError($field, 'This field is required');
                    isValid = false;
                } else {
                    WPBreachPublic.clearFieldError($field);
                }
            });
            
            // Validate email if provided
            var $emailField = $form.find('[name="reporter_email"]');
            if ($emailField.val() && !WPBreachPublic.isValidEmail($emailField.val())) {
                WPBreachPublic.showFieldError($emailField, 'Please enter a valid email address');
                isValid = false;
            }
            
            // Validate URL if provided
            var $urlField = $form.find('[name="issue_url"]');
            if ($urlField.val() && !WPBreachPublic.isValidURL($urlField.val())) {
                WPBreachPublic.showFieldError($urlField, 'Please enter a valid URL');
                isValid = false;
            }
            
            return isValid;
        },

        /**
         * Validate individual field
         */
        validateField: function() {
            var $field = $(this);
            var value = $field.val().trim();
            var fieldName = $field.attr('name');
            
            // Clear previous errors
            WPBreachPublic.clearFieldError($field);
            
            // Required field validation
            if ($field.prop('required') && !value) {
                WPBreachPublic.showFieldError($field, 'This field is required');
                return;
            }
            
            // Field-specific validation
            switch (fieldName) {
                case 'reporter_email':
                    if (value && !WPBreachPublic.isValidEmail(value)) {
                        WPBreachPublic.showFieldError($field, 'Please enter a valid email address');
                    }
                    break;
                    
                case 'issue_url':
                    if (value && !WPBreachPublic.isValidURL(value)) {
                        WPBreachPublic.showFieldError($field, 'Please enter a valid URL');
                    }
                    break;
                    
                case 'issue_description':
                    if (value && value.length < 10) {
                        WPBreachPublic.showFieldError($field, 'Please provide more details (at least 10 characters)');
                    }
                    break;
            }
        },

        /**
         * Show field error
         */
        showFieldError: function($field, message) {
            var $group = $field.closest('.wp-breach-form-group');
            var $error = $group.find('.wp-breach-field-error');
            
            if (!$error.length) {
                $error = $('<div class="wp-breach-field-error"></div>');
                $group.append($error);
            }
            
            $error.text(message).show();
            $field.addClass('error');
        },

        /**
         * Clear field error
         */
        clearFieldError: function($field) {
            var $group = $field.closest('.wp-breach-form-group');
            $group.find('.wp-breach-field-error').hide();
            $field.removeClass('error');
        },

        /**
         * Update character count
         */
        updateCharacterCount: function() {
            var $textarea = $(this);
            var currentLength = $textarea.val().length;
            var maxLength = $textarea.attr('maxlength') || 1000;
            var $counter = $textarea.siblings('.wp-breach-char-counter');
            
            if (!$counter.length) {
                $counter = $('<div class="wp-breach-char-counter"></div>');
                $textarea.after($counter);
            }
            
            $counter.text(currentLength + '/' + maxLength);
            
            if (currentLength > maxLength * 0.9) {
                $counter.addClass('warning');
            } else {
                $counter.removeClass('warning');
            }
        },

        /**
         * Auto-fill current URL
         */
        autoFillCurrentURL: function() {
            var $urlField = $('.wp-breach-report-form [name="issue_url"]');
            if ($urlField.length && !$urlField.val()) {
                $urlField.val(window.location.href);
            }
        },

        /**
         * Toggle security tips
         */
        toggleSecurityTips: function(e) {
            e.preventDefault();
            
            var $toggle = $(this);
            var $tips = $toggle.next('.wp-breach-security-tips');
            
            $tips.slideToggle();
            $toggle.toggleClass('active');
        },

        /**
         * Animate status change
         */
        animateStatusChange: function() {
            var $statusIcons = $('.wp-breach-status-icon');
            
            $statusIcons.each(function(index) {
                var $icon = $(this);
                setTimeout(function() {
                    $icon.addClass('animate-in');
                }, index * 200);
            });
        },

        /**
         * Monitor user activity for suspicious patterns
         */
        monitorUserActivity: function() {
            var suspiciousKeywords = ['<script', 'javascript:', 'vbscript:', 'onload=', 'onerror='];
            
            $(document).on('input', 'input, textarea', function() {
                var value = $(this).val().toLowerCase();
                
                for (var i = 0; i < suspiciousKeywords.length; i++) {
                    if (value.indexOf(suspiciousKeywords[i]) !== -1) {
                        WPBreachPublic.reportSuspiciousActivity('suspicious_input', {
                            keyword: suspiciousKeywords[i],
                            field: $(this).attr('name') || 'unknown'
                        });
                        break;
                    }
                }
            });
        },

        /**
         * Check for security headers
         */
        checkSecurityHeaders: function() {
            // This would typically be done server-side, but we can check some client-side indicators
            if (
                window.location.protocol !== 'https:' &&
                !WPBreachPublic.isLocalhostLike(window.location.hostname)
            ) {
                WPBreachPublic.showAlert('This site is not using HTTPS. Your data may not be secure.', 'warning');
            }
        },

        /**
         * Report suspicious activity
         */
        reportSuspiciousActivity: function(type, data) {
            $.ajax({
                url: wp_breach_public_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'wp_breach_report_suspicious_activity',
                    activity_type: type,
                    activity_data: JSON.stringify(data),
                    nonce: wp_breach_public_ajax.nonce
                }
            });
        },

        /**
         * Show alert message
         */
        showAlert: function(message, type) {
            type = type || 'info';
            
            var $alert = $('<div class="wp-breach-alert ' + type + '">' + message + '</div>');
            
            // Find a good place to show the alert
            var $target = $('.wp-breach-report-form, .wp-breach-security-widget').first();
            
            if ($target.length) {
                $target.before($alert);
            } else {
                $('body').prepend($alert);
            }
            
            // Auto-hide after 5 seconds
            setTimeout(function() {
                $alert.fadeOut(function() {
                    $(this).remove();
                });
            }, 5000);
        },

        /**
         * Validate email address
         */
        isValidEmail: function(email) {
            var emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            return emailRegex.test(email);
        },

        /**
         * Validate URL
         */
        isValidURL: function(url) {
            try {
                new URL(url);
                return true;
            } catch (e) {
                return false;
            }
        }
    };

    // Initialize when document is ready
    $(document).ready(function() {
        WPBreachPublic.init();
    });

    // Also expose globally for external access
    window.WPBreachPublic = WPBreachPublic;

})( jQuery );
