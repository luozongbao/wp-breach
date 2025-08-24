/**
 * WP-Breach Settings Admin JavaScript
 *
 * Handles client-side functionality for the settings administration interface.
 *
 * @package WP_Breach
 * @since   1.0.0
 */

(function($) {
    'use strict';

    /**
     * Settings Admin Handler
     */
    const WpBreachSettingsAdmin = {
        
        /**
         * Initialize the settings admin interface
         */
        init: function() {
            this.bindEvents();
            this.initDependencies();
            this.initRangeSliders();
            this.initFormValidation();
            this.initTooltips();
        },

        /**
         * Bind event handlers
         */
        bindEvents: function() {
            // Import/Export handlers
            $('.wp-breach-export-settings').on('click', this.handleExportSettings);
            $('.wp-breach-import-settings').on('click', this.handleImportSettings);
            $('#settings-import-file').on('change', this.processImportFile);
            
            // Reset handlers
            $('.wp-breach-reset-all').on('click', this.handleResetAllSettings);
            $('.wp-breach-reset-group').on('click', this.handleResetGroupSettings);
            
            // Profile handlers
            $('.wp-breach-apply-profile').on('click', this.handleApplyProfile);
            
            // Form submission
            $('.wp-breach-settings-form').on('submit', this.handleFormSubmission);
            
            // Field change handlers
            $('input, select, textarea').on('change', this.handleFieldChange);
            
            // Tab switching
            $('.wp-breach-nav-tabs .nav-tab').on('click', this.handleTabSwitch);
        },

        /**
         * Initialize field dependencies
         */
        initDependencies: function() {
            const self = this;
            
            $('[data-dependency]').each(function() {
                const $field = $(this);
                const dependency = JSON.parse($field.attr('data-dependency'));
                const $dependentField = $('[name*="[' + dependency.field + ']"]');
                
                // Initial check
                self.checkDependency($field, $dependentField, dependency.value);
                
                // Monitor dependency field changes
                $dependentField.on('change', function() {
                    self.checkDependency($field, $dependentField, dependency.value);
                });
            });
        },

        /**
         * Check field dependency
         */
        checkDependency: function($field, $dependentField, requiredValue) {
            const $row = $field.closest('tr');
            let currentValue = $dependentField.val();
            
            // Handle checkbox values
            if ($dependentField.is(':checkbox')) {
                currentValue = $dependentField.is(':checked');
            }
            
            if (currentValue == requiredValue) {
                $row.show().removeClass('dependency-disabled');
                $field.prop('disabled', false);
            } else {
                $row.hide().addClass('dependency-disabled');
                $field.prop('disabled', true);
            }
        },

        /**
         * Initialize range sliders
         */
        initRangeSliders: function() {
            $('input[type="range"]').each(function() {
                const $range = $(this);
                const $valueDisplay = $range.siblings('.range-value');
                
                $range.on('input', function() {
                    $valueDisplay.text($(this).val());
                });
            });
        },

        /**
         * Initialize form validation
         */
        initFormValidation: function() {
            const self = this;
            
            // Real-time validation
            $('input, select, textarea').on('blur', function() {
                self.validateField($(this));
            });
            
            // Clear validation on focus
            $('input, select, textarea').on('focus', function() {
                self.clearFieldValidation($(this));
            });
        },

        /**
         * Initialize tooltips
         */
        initTooltips: function() {
            // Help text tooltips are handled via CSS hover
            // This could be enhanced with a tooltip library if needed
        },

        /**
         * Validate individual field
         */
        validateField: function($field) {
            const value = $field.val();
            const type = $field.attr('type');
            const required = $field.prop('required');
            let isValid = true;
            let errorMessage = '';

            // Clear previous validation
            this.clearFieldValidation($field);

            // Required validation
            if (required && !value) {
                isValid = false;
                errorMessage = wpBreachSettings.strings.fieldRequired || 'This field is required';
            }

            // Type-specific validation
            if (value && !isValid !== false) {
                switch (type) {
                    case 'email':
                        if (!this.isValidEmail(value)) {
                            isValid = false;
                            errorMessage = 'Please enter a valid email address';
                        }
                        break;
                    case 'url':
                        if (!this.isValidUrl(value)) {
                            isValid = false;
                            errorMessage = 'Please enter a valid URL';
                        }
                        break;
                    case 'number':
                        const min = $field.attr('min');
                        const max = $field.attr('max');
                        const numValue = parseFloat(value);
                        
                        if (isNaN(numValue)) {
                            isValid = false;
                            errorMessage = 'Please enter a valid number';
                        } else if (min && numValue < parseFloat(min)) {
                            isValid = false;
                            errorMessage = `Value must be at least ${min}`;
                        } else if (max && numValue > parseFloat(max)) {
                            isValid = false;
                            errorMessage = `Value must be no more than ${max}`;
                        }
                        break;
                }
            }

            // Apply validation state
            if (!isValid) {
                $field.addClass('field-error');
                $field.after(`<span class="field-error-message">${errorMessage}</span>`);
            } else if (value) {
                $field.addClass('field-success');
            }

            return isValid;
        },

        /**
         * Clear field validation state
         */
        clearFieldValidation: function($field) {
            $field.removeClass('field-error field-success');
            $field.siblings('.field-error-message, .field-success-message').remove();
        },

        /**
         * Handle form submission
         */
        handleFormSubmission: function(e) {
            const $form = $(this);
            const $submitButton = $form.find('input[type="submit"]');
            let isValid = true;

            // Validate all fields
            $form.find('input, select, textarea').each(function() {
                if (!WpBreachSettingsAdmin.validateField($(this))) {
                    isValid = false;
                }
            });

            if (!isValid) {
                e.preventDefault();
                WpBreachSettingsAdmin.showNotice('Please correct the errors below', 'error');
                return false;
            }

            // Show loading state
            $submitButton.prop('disabled', true);
            $form.addClass('loading');
        },

        /**
         * Handle field changes
         */
        handleFieldChange: function() {
            const $field = $(this);
            
            // Mark form as dirty
            $field.closest('form').data('dirty', true);
            
            // Clear any validation errors
            WpBreachSettingsAdmin.clearFieldValidation($field);
        },

        /**
         * Handle tab switching
         */
        handleTabSwitch: function(e) {
            const $form = $('.wp-breach-settings-form');
            
            // Check if form is dirty
            if ($form.data('dirty')) {
                if (!confirm('You have unsaved changes. Are you sure you want to leave this tab?')) {
                    e.preventDefault();
                    return false;
                }
            }
        },

        /**
         * Handle settings export
         */
        handleExportSettings: function(e) {
            e.preventDefault();
            
            const $button = $(this);
            const originalText = $button.text();
            
            $button.prop('disabled', true).text('Exporting...');
            
            $.ajax({
                url: wpBreachSettings.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'wp_breach_settings_export',
                    nonce: wpBreachSettings.nonce
                },
                success: function(response) {
                    if (response.success) {
                        WpBreachSettingsAdmin.downloadSettings(response.data.data, response.data.filename);
                        WpBreachSettingsAdmin.showNotice(wpBreachSettings.strings.exportSuccess, 'success');
                    } else {
                        WpBreachSettingsAdmin.showNotice(response.data || wpBreachSettings.strings.error, 'error');
                    }
                },
                error: function() {
                    WpBreachSettingsAdmin.showNotice(wpBreachSettings.strings.error, 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        },

        /**
         * Handle settings import
         */
        handleImportSettings: function(e) {
            e.preventDefault();
            $('#settings-import-file').click();
        },

        /**
         * Process import file
         */
        processImportFile: function(e) {
            const file = e.target.files[0];
            
            if (!file) {
                return;
            }
            
            if (file.type !== 'application/json') {
                WpBreachSettingsAdmin.showNotice('Please select a valid JSON file', 'error');
                return;
            }
            
            if (!confirm(wpBreachSettings.strings.confirmImport)) {
                $(this).val('');
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'wp_breach_settings_import');
            formData.append('nonce', wpBreachSettings.nonce);
            formData.append('settings_file', file);
            
            $.ajax({
                url: wpBreachSettings.ajaxUrl,
                type: 'POST',
                data: formData,
                processData: false,
                contentType: false,
                success: function(response) {
                    if (response.success) {
                        WpBreachSettingsAdmin.showNotice(wpBreachSettings.strings.importSuccess, 'success');
                        setTimeout(() => location.reload(), 1500);
                    } else {
                        WpBreachSettingsAdmin.showNotice(response.data || wpBreachSettings.strings.error, 'error');
                    }
                },
                error: function() {
                    WpBreachSettingsAdmin.showNotice(wpBreachSettings.strings.error, 'error');
                },
                complete: function() {
                    $('#settings-import-file').val('');
                }
            });
        },

        /**
         * Handle reset all settings
         */
        handleResetAllSettings: function(e) {
            e.preventDefault();
            
            if (!confirm(wpBreachSettings.strings.confirmReset)) {
                return;
            }
            
            WpBreachSettingsAdmin.resetSettings('all');
        },

        /**
         * Handle reset group settings
         */
        handleResetGroupSettings: function(e) {
            e.preventDefault();
            
            const group = $(this).data('group');
            
            if (!confirm(`Are you sure you want to reset ${group} settings to their default values?`)) {
                return;
            }
            
            WpBreachSettingsAdmin.resetSettings(group);
        },

        /**
         * Reset settings
         */
        resetSettings: function(group) {
            const $button = group === 'all' ? $('.wp-breach-reset-all') : $(`.wp-breach-reset-group[data-group="${group}"]`);
            const originalText = $button.text();
            
            $button.prop('disabled', true).text('Resetting...');
            
            $.ajax({
                url: wpBreachSettings.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'wp_breach_settings_reset',
                    nonce: wpBreachSettings.nonce,
                    group: group
                },
                success: function(response) {
                    if (response.success) {
                        WpBreachSettingsAdmin.showNotice(wpBreachSettings.strings.resetSuccess, 'success');
                        setTimeout(() => location.reload(), 1500);
                    } else {
                        WpBreachSettingsAdmin.showNotice(response.data || wpBreachSettings.strings.error, 'error');
                    }
                },
                error: function() {
                    WpBreachSettingsAdmin.showNotice(wpBreachSettings.strings.error, 'error');
                },
                complete: function() {
                    $button.prop('disabled', false).text(originalText);
                }
            });
        },

        /**
         * Handle apply configuration profile
         */
        handleApplyProfile: function(e) {
            e.preventDefault();
            
            const profile = $(this).data('profile');
            const $button = $(this);
            const originalText = $button.text();
            
            if (!confirm(`Apply ${profile} configuration profile? This will update multiple settings.`)) {
                return;
            }
            
            $button.prop('disabled', true).text('Applying...');
            
            // Profile configurations
            const profiles = {
                basic: {
                    general: {
                        security_level: 'relaxed',
                        debug_mode: false,
                        auto_updates: true
                    },
                    scanning: {
                        default_scan_type: 'quick',
                        scan_intensity: 3,
                        deep_analysis: false,
                        schedule_frequency: 'weekly'
                    },
                    security: {
                        auto_fix_enabled: true,
                        auto_fix_severity: 'low',
                        monitoring_enabled: true
                    }
                },
                advanced: {
                    general: {
                        security_level: 'strict',
                        debug_mode: false,
                        auto_updates: true
                    },
                    scanning: {
                        default_scan_type: 'full',
                        scan_intensity: 8,
                        deep_analysis: true,
                        schedule_frequency: 'daily'
                    },
                    security: {
                        auto_fix_enabled: false,
                        monitoring_enabled: true,
                        strict_file_permissions: true
                    }
                },
                development: {
                    general: {
                        security_level: 'standard',
                        debug_mode: true,
                        plugin_mode: 'development'
                    },
                    scanning: {
                        default_scan_type: 'custom',
                        scan_intensity: 5,
                        schedule_frequency: 'hourly'
                    },
                    advanced: {
                        logging_level: 'debug'
                    }
                }
            };
            
            if (profiles[profile]) {
                this.applyProfileSettings(profiles[profile], function(success) {
                    if (success) {
                        WpBreachSettingsAdmin.showNotice(`${profile} profile applied successfully`, 'success');
                        setTimeout(() => location.reload(), 1500);
                    } else {
                        WpBreachSettingsAdmin.showNotice('Failed to apply profile', 'error');
                    }
                    $button.prop('disabled', false).text(originalText);
                });
            }
        },

        /**
         * Apply profile settings
         */
        applyProfileSettings: function(profileSettings, callback) {
            // This would typically make an AJAX call to apply the profile
            // For now, we'll simulate it by updating the current form values
            
            Object.keys(profileSettings).forEach(group => {
                Object.keys(profileSettings[group]).forEach(setting => {
                    const $field = $(`[name*="[${setting}]"]`);
                    const value = profileSettings[group][setting];
                    
                    if ($field.is(':checkbox')) {
                        $field.prop('checked', value);
                    } else {
                        $field.val(value);
                    }
                    
                    $field.trigger('change');
                });
            });
            
            if (callback) callback(true);
        },

        /**
         * Download settings as JSON file
         */
        downloadSettings: function(data, filename) {
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        },

        /**
         * Show admin notice
         */
        showNotice: function(message, type = 'info') {
            const $notice = $(`
                <div class="notice notice-${type} is-dismissible">
                    <p>${message}</p>
                    <button type="button" class="notice-dismiss">
                        <span class="screen-reader-text">Dismiss this notice.</span>
                    </button>
                </div>
            `);
            
            $('.wp-breach-settings h1').after($notice);
            
            // Auto-dismiss success notices
            if (type === 'success') {
                setTimeout(() => $notice.fadeOut(), 3000);
            }
            
            // Handle dismiss button
            $notice.find('.notice-dismiss').on('click', function() {
                $notice.fadeOut();
            });
        },

        /**
         * Validation helpers
         */
        isValidEmail: function(email) {
            const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            return re.test(email);
        },

        isValidUrl: function(url) {
            try {
                new URL(url);
                return true;
            } catch {
                return false;
            }
        }
    };

    /**
     * Initialize when document is ready
     */
    $(document).ready(function() {
        WpBreachSettingsAdmin.init();
    });

    /**
     * Handle unsaved changes warning
     */
    $(window).on('beforeunload', function(e) {
        if ($('.wp-breach-settings-form').data('dirty')) {
            const message = 'You have unsaved changes. Are you sure you want to leave?';
            e.returnValue = message;
            return message;
        }
    });

})(jQuery);
