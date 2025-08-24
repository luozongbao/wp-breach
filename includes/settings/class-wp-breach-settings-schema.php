<?php

/**
 * Settings Schema for WP-Breach.
 *
 * This class defines the structure, validation rules, and default values
 * for all plugin settings organized into logical groups.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/settings
 */

/**
 * The settings schema class.
 *
 * Defines the complete settings structure with validation rules,
 * default values, help text, and permissions for all plugin settings.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/settings
 * @author     WP Breach Team
 */
class WP_Breach_Settings_Schema {

    /**
     * Settings schema definition.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $schema    Complete settings schema.
     */
    private $schema;

    /**
     * Initialize the settings schema.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->define_schema();
    }

    /**
     * Define the complete settings schema.
     *
     * @since    1.0.0
     * @access   private
     */
    private function define_schema() {
        $this->schema = array(
            'general' => array(
                'label' => __('General Settings', 'wp-breach'),
                'description' => __('Core plugin configuration and behavior settings', 'wp-breach'),
                'icon' => 'admin-generic',
                'priority' => 1,
                'permissions' => array(
                    'read' => 'manage_options',
                    'write' => 'manage_options'
                ),
                'settings' => array(
                    'security_level' => array(
                        'type' => 'select',
                        'label' => __('Security Level', 'wp-breach'),
                        'description' => __('Overall security enforcement level for the plugin', 'wp-breach'),
                        'help' => __('Relaxed mode performs basic checks with minimal performance impact. Standard mode provides balanced security and performance. Strict mode offers maximum security but may impact site functionality.', 'wp-breach'),
                        'options' => array(
                            'relaxed' => __('Relaxed - Basic protection', 'wp-breach'),
                            'standard' => __('Standard - Recommended for most sites', 'wp-breach'),
                            'strict' => __('Strict - Maximum security (may affect functionality)', 'wp-breach')
                        ),
                        'default' => 'standard',
                        'validation' => array(
                            'required' => true,
                            'enum' => array('relaxed', 'standard', 'strict')
                        )
                    ),
                    'plugin_mode' => array(
                        'type' => 'select',
                        'label' => __('Plugin Mode', 'wp-breach'),
                        'description' => __('Environment mode affects logging, debugging, and performance settings', 'wp-breach'),
                        'options' => array(
                            'development' => __('Development', 'wp-breach'),
                            'staging' => __('Staging', 'wp-breach'),
                            'production' => __('Production', 'wp-breach')
                        ),
                        'default' => 'production',
                        'validation' => array(
                            'required' => true,
                            'enum' => array('development', 'staging', 'production')
                        )
                    ),
                    'debug_mode' => array(
                        'type' => 'checkbox',
                        'label' => __('Enable Debug Mode', 'wp-breach'),
                        'description' => __('Enable detailed logging for troubleshooting purposes', 'wp-breach'),
                        'help' => __('Debug mode creates detailed logs that can help diagnose issues. Disable in production environments to improve performance.', 'wp-breach'),
                        'default' => false,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'language' => array(
                        'type' => 'select',
                        'label' => __('Interface Language', 'wp-breach'),
                        'description' => __('Plugin interface language', 'wp-breach'),
                        'options' => $this->get_available_languages(),
                        'default' => 'en_US',
                        'validation' => array(
                            'type' => 'string',
                            'maxlength' => 10
                        )
                    ),
                    'timezone' => array(
                        'type' => 'select',
                        'label' => __('Timezone', 'wp-breach'),
                        'description' => __('Timezone for reports and scheduling', 'wp-breach'),
                        'options' => $this->get_timezone_options(),
                        'default' => get_option('timezone_string', 'UTC'),
                        'validation' => array(
                            'type' => 'string'
                        )
                    ),
                    'data_retention_days' => array(
                        'type' => 'number',
                        'label' => __('Data Retention (days)', 'wp-breach'),
                        'description' => __('How long to keep scan results, logs, and historical data', 'wp-breach'),
                        'help' => __('Longer retention periods provide better trend analysis but require more storage space.', 'wp-breach'),
                        'min' => 1,
                        'max' => 365,
                        'step' => 1,
                        'default' => 90,
                        'validation' => array(
                            'type' => 'integer',
                            'min' => 1,
                            'max' => 365
                        )
                    ),
                    'auto_updates' => array(
                        'type' => 'checkbox',
                        'label' => __('Enable Auto Updates', 'wp-breach'),
                        'description' => __('Automatically update plugin definitions and signatures', 'wp-breach'),
                        'default' => true,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    )
                )
            ),
            'scanning' => array(
                'label' => __('Scanning Configuration', 'wp-breach'),
                'description' => __('Configure security scanning behavior and performance settings', 'wp-breach'),
                'icon' => 'search',
                'priority' => 2,
                'permissions' => array(
                    'read' => 'manage_options',
                    'write' => 'manage_options'
                ),
                'settings' => array(
                    'default_scan_type' => array(
                        'type' => 'select',
                        'label' => __('Default Scan Type', 'wp-breach'),
                        'description' => __('Default scanning mode for automated and manual scans', 'wp-breach'),
                        'options' => array(
                            'quick' => __('Quick Scan (5-10 minutes)', 'wp-breach'),
                            'full' => __('Full Scan (15-30 minutes)', 'wp-breach'),
                            'custom' => __('Custom Scan', 'wp-breach')
                        ),
                        'default' => 'full',
                        'validation' => array(
                            'required' => true,
                            'enum' => array('quick', 'full', 'custom')
                        )
                    ),
                    'scan_intensity' => array(
                        'type' => 'range',
                        'label' => __('Scan Intensity', 'wp-breach'),
                        'description' => __('Scanner thoroughness vs. performance balance', 'wp-breach'),
                        'help' => __('Higher intensity provides more thorough scanning but uses more server resources and takes longer to complete.', 'wp-breach'),
                        'min' => 1,
                        'max' => 10,
                        'step' => 1,
                        'default' => 5,
                        'validation' => array(
                            'type' => 'integer',
                            'min' => 1,
                            'max' => 10
                        )
                    ),
                    'memory_limit' => array(
                        'type' => 'number',
                        'label' => __('Memory Limit (MB)', 'wp-breach'),
                        'description' => __('Maximum memory usage during scans', 'wp-breach'),
                        'min' => 64,
                        'max' => 1024,
                        'step' => 32,
                        'default' => 256,
                        'validation' => array(
                            'type' => 'integer',
                            'min' => 64,
                            'max' => 1024
                        )
                    ),
                    'time_limit' => array(
                        'type' => 'number',
                        'label' => __('Time Limit (seconds)', 'wp-breach'),
                        'description' => __('Maximum execution time for individual scan operations', 'wp-breach'),
                        'min' => 30,
                        'max' => 3600,
                        'step' => 30,
                        'default' => 300,
                        'validation' => array(
                            'type' => 'integer',
                            'min' => 30,
                            'max' => 3600
                        )
                    ),
                    'scan_targets' => array(
                        'type' => 'multiselect',
                        'label' => __('Default Scan Targets', 'wp-breach'),
                        'description' => __('Components to include in default scans', 'wp-breach'),
                        'options' => array(
                            'core' => __('WordPress Core', 'wp-breach'),
                            'plugins' => __('Plugins', 'wp-breach'),
                            'themes' => __('Themes', 'wp-breach'),
                            'uploads' => __('Uploads Directory', 'wp-breach'),
                            'database' => __('Database', 'wp-breach'),
                            'users' => __('User Accounts', 'wp-breach'),
                            'files' => __('File System', 'wp-breach')
                        ),
                        'default' => array('core', 'plugins', 'themes', 'database'),
                        'validation' => array(
                            'type' => 'array',
                            'items' => array(
                                'enum' => array('core', 'plugins', 'themes', 'uploads', 'database', 'users', 'files')
                            )
                        )
                    ),
                    'deep_analysis' => array(
                        'type' => 'checkbox',
                        'label' => __('Enable Deep Analysis', 'wp-breach'),
                        'description' => __('Perform detailed code analysis and pattern matching', 'wp-breach'),
                        'help' => __('Deep analysis can detect more sophisticated threats but significantly increases scan time.', 'wp-breach'),
                        'default' => false,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'external_checks' => array(
                        'type' => 'checkbox',
                        'label' => __('External Database Checks', 'wp-breach'),
                        'description' => __('Check against external vulnerability databases', 'wp-breach'),
                        'default' => true,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'schedule_enabled' => array(
                        'type' => 'checkbox',
                        'label' => __('Enable Scheduled Scans', 'wp-breach'),
                        'description' => __('Automatically run scans on a schedule', 'wp-breach'),
                        'default' => true,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'schedule_frequency' => array(
                        'type' => 'select',
                        'label' => __('Scan Frequency', 'wp-breach'),
                        'description' => __('How often to run automated scans', 'wp-breach'),
                        'options' => array(
                            'hourly' => __('Every Hour', 'wp-breach'),
                            'daily' => __('Daily', 'wp-breach'),
                            'weekly' => __('Weekly', 'wp-breach'),
                            'monthly' => __('Monthly', 'wp-breach')
                        ),
                        'default' => 'daily',
                        'validation' => array(
                            'enum' => array('hourly', 'daily', 'weekly', 'monthly')
                        ),
                        'dependency' => array(
                            'field' => 'schedule_enabled',
                            'value' => true
                        )
                    )
                )
            ),
            'notifications' => array(
                'label' => __('Notification Settings', 'wp-breach'),
                'description' => __('Configure alert delivery and notification preferences', 'wp-breach'),
                'icon' => 'email-alt',
                'priority' => 3,
                'permissions' => array(
                    'read' => 'manage_options',
                    'write' => 'manage_options'
                ),
                'settings' => array(
                    'email_notifications' => array(
                        'type' => 'checkbox',
                        'label' => __('Enable Email Notifications', 'wp-breach'),
                        'description' => __('Send security alerts via email', 'wp-breach'),
                        'default' => true,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'notification_recipients' => array(
                        'type' => 'textarea',
                        'label' => __('Notification Recipients', 'wp-breach'),
                        'description' => __('Email addresses to receive notifications (one per line)', 'wp-breach'),
                        'help' => __('Enter one email address per line. All addresses will receive security notifications.', 'wp-breach'),
                        'rows' => 5,
                        'default' => get_option('admin_email'),
                        'validation' => array(
                            'type' => 'string',
                            'custom' => 'validate_email_list'
                        ),
                        'dependency' => array(
                            'field' => 'email_notifications',
                            'value' => true
                        )
                    ),
                    'alert_threshold' => array(
                        'type' => 'select',
                        'label' => __('Alert Threshold', 'wp-breach'),
                        'description' => __('Minimum severity level for email notifications', 'wp-breach'),
                        'options' => array(
                            'critical' => __('Critical vulnerabilities only', 'wp-breach'),
                            'high' => __('High and above', 'wp-breach'),
                            'medium' => __('Medium and above', 'wp-breach'),
                            'low' => __('All vulnerabilities', 'wp-breach')
                        ),
                        'default' => 'high',
                        'validation' => array(
                            'enum' => array('critical', 'high', 'medium', 'low')
                        )
                    ),
                    'dashboard_notifications' => array(
                        'type' => 'checkbox',
                        'label' => __('Dashboard Notifications', 'wp-breach'),
                        'description' => __('Show notifications in WordPress admin dashboard', 'wp-breach'),
                        'default' => true,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'real_time_alerts' => array(
                        'type' => 'checkbox',
                        'label' => __('Real-time Alerts', 'wp-breach'),
                        'description' => __('Send immediate notifications for critical threats', 'wp-breach'),
                        'default' => true,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'alert_grouping' => array(
                        'type' => 'checkbox',
                        'label' => __('Group Similar Alerts', 'wp-breach'),
                        'description' => __('Combine similar alerts to prevent notification spam', 'wp-breach'),
                        'default' => true,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'quiet_hours_enabled' => array(
                        'type' => 'checkbox',
                        'label' => __('Enable Quiet Hours', 'wp-breach'),
                        'description' => __('Suppress non-critical notifications during specified hours', 'wp-breach'),
                        'default' => false,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'quiet_hours_start' => array(
                        'type' => 'time',
                        'label' => __('Quiet Hours Start', 'wp-breach'),
                        'description' => __('Start time for quiet hours', 'wp-breach'),
                        'default' => '22:00',
                        'validation' => array(
                            'type' => 'string',
                            'pattern' => '/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/'
                        ),
                        'dependency' => array(
                            'field' => 'quiet_hours_enabled',
                            'value' => true
                        )
                    ),
                    'quiet_hours_end' => array(
                        'type' => 'time',
                        'label' => __('Quiet Hours End', 'wp-breach'),
                        'description' => __('End time for quiet hours', 'wp-breach'),
                        'default' => '08:00',
                        'validation' => array(
                            'type' => 'string',
                            'pattern' => '/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/'
                        ),
                        'dependency' => array(
                            'field' => 'quiet_hours_enabled',
                            'value' => true
                        )
                    )
                )
            ),
            'security' => array(
                'label' => __('Security Preferences', 'wp-breach'),
                'description' => __('Configure security features and automated responses', 'wp-breach'),
                'icon' => 'shield',
                'priority' => 4,
                'permissions' => array(
                    'read' => 'manage_options',
                    'write' => 'manage_options'
                ),
                'settings' => array(
                    'auto_fix_enabled' => array(
                        'type' => 'checkbox',
                        'label' => __('Enable Automated Fixes', 'wp-breach'),
                        'description' => __('Automatically apply fixes for known vulnerabilities', 'wp-breach'),
                        'help' => __('Automated fixes are applied only for well-tested, low-risk solutions. Critical changes always require manual approval.', 'wp-breach'),
                        'default' => false,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'auto_fix_severity' => array(
                        'type' => 'select',
                        'label' => __('Auto-fix Severity Limit', 'wp-breach'),
                        'description' => __('Maximum severity level for automatic fixes', 'wp-breach'),
                        'options' => array(
                            'low' => __('Low severity only', 'wp-breach'),
                            'medium' => __('Medium and below', 'wp-breach'),
                            'high' => __('High and below', 'wp-breach'),
                            'critical' => __('All severities', 'wp-breach')
                        ),
                        'default' => 'low',
                        'validation' => array(
                            'enum' => array('low', 'medium', 'high', 'critical')
                        ),
                        'dependency' => array(
                            'field' => 'auto_fix_enabled',
                            'value' => true
                        )
                    ),
                    'backup_before_fix' => array(
                        'type' => 'checkbox',
                        'label' => __('Create Backup Before Fixes', 'wp-breach'),
                        'description' => __('Automatically create backups before applying fixes', 'wp-breach'),
                        'default' => true,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'monitoring_enabled' => array(
                        'type' => 'checkbox',
                        'label' => __('Enable Real-time Monitoring', 'wp-breach'),
                        'description' => __('Monitor file changes and suspicious activities in real-time', 'wp-breach'),
                        'default' => true,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'whitelist_enabled' => array(
                        'type' => 'checkbox',
                        'label' => __('Enable Whitelist Management', 'wp-breach'),
                        'description' => __('Allow trusted files, IPs, and users to bypass certain checks', 'wp-breach'),
                        'default' => true,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'strict_file_permissions' => array(
                        'type' => 'checkbox',
                        'label' => __('Enforce Strict File Permissions', 'wp-breach'),
                        'description' => __('Monitor and enforce secure file permissions', 'wp-breach'),
                        'default' => false,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'api_security_enabled' => array(
                        'type' => 'checkbox',
                        'label' => __('Enable API Security', 'wp-breach'),
                        'description' => __('Secure REST API endpoints and monitor API usage', 'wp-breach'),
                        'default' => true,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'login_security_enabled' => array(
                        'type' => 'checkbox',
                        'label' => __('Enable Login Security', 'wp-breach'),
                        'description' => __('Monitor login attempts and detect brute force attacks', 'wp-breach'),
                        'default' => true,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'max_login_attempts' => array(
                        'type' => 'number',
                        'label' => __('Max Login Attempts', 'wp-breach'),
                        'description' => __('Maximum failed login attempts before blocking', 'wp-breach'),
                        'min' => 3,
                        'max' => 20,
                        'step' => 1,
                        'default' => 5,
                        'validation' => array(
                            'type' => 'integer',
                            'min' => 3,
                            'max' => 20
                        ),
                        'dependency' => array(
                            'field' => 'login_security_enabled',
                            'value' => true
                        )
                    )
                )
            ),
            'advanced' => array(
                'label' => __('Advanced Configuration', 'wp-breach'),
                'description' => __('Advanced settings for power users and developers', 'wp-breach'),
                'icon' => 'admin-tools',
                'priority' => 5,
                'permissions' => array(
                    'read' => 'manage_options',
                    'write' => 'manage_options'
                ),
                'settings' => array(
                    'api_enabled' => array(
                        'type' => 'checkbox',
                        'label' => __('Enable API Access', 'wp-breach'),
                        'description' => __('Allow external access to plugin API endpoints', 'wp-breach'),
                        'default' => false,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'api_key' => array(
                        'type' => 'text',
                        'label' => __('API Key', 'wp-breach'),
                        'description' => __('Authentication key for API access', 'wp-breach'),
                        'default' => '',
                        'validation' => array(
                            'type' => 'string',
                            'minlength' => 32,
                            'maxlength' => 64
                        ),
                        'sensitive' => true,
                        'dependency' => array(
                            'field' => 'api_enabled',
                            'value' => true
                        )
                    ),
                    'external_integrations' => array(
                        'type' => 'multiselect',
                        'label' => __('External Integrations', 'wp-breach'),
                        'description' => __('Enable integrations with external services', 'wp-breach'),
                        'options' => array(
                            'wpscan' => __('WPScan API', 'wp-breach'),
                            'nvd' => __('National Vulnerability Database', 'wp-breach'),
                            'virustotal' => __('VirusTotal', 'wp-breach'),
                            'cloudflare' => __('Cloudflare Security', 'wp-breach')
                        ),
                        'default' => array('wpscan', 'nvd'),
                        'validation' => array(
                            'type' => 'array',
                            'items' => array(
                                'enum' => array('wpscan', 'nvd', 'virustotal', 'cloudflare')
                            )
                        )
                    ),
                    'custom_rules_enabled' => array(
                        'type' => 'checkbox',
                        'label' => __('Enable Custom Rules', 'wp-breach'),
                        'description' => __('Allow custom vulnerability detection rules', 'wp-breach'),
                        'default' => false,
                        'validation' => array(
                            'type' => 'boolean'
                        )
                    ),
                    'performance_mode' => array(
                        'type' => 'select',
                        'label' => __('Performance Mode', 'wp-breach'),
                        'description' => __('Balance between security and performance', 'wp-breach'),
                        'options' => array(
                            'conservative' => __('Conservative - Minimal resource usage', 'wp-breach'),
                            'balanced' => __('Balanced - Recommended for most sites', 'wp-breach'),
                            'aggressive' => __('Aggressive - Maximum security checks', 'wp-breach')
                        ),
                        'default' => 'balanced',
                        'validation' => array(
                            'enum' => array('conservative', 'balanced', 'aggressive')
                        )
                    ),
                    'logging_level' => array(
                        'type' => 'select',
                        'label' => __('Logging Level', 'wp-breach'),
                        'description' => __('Amount of detail in security logs', 'wp-breach'),
                        'options' => array(
                            'none' => __('No Logging', 'wp-breach'),
                            'errors' => __('Errors Only', 'wp-breach'),
                            'warnings' => __('Warnings and Errors', 'wp-breach'),
                            'info' => __('Informational', 'wp-breach'),
                            'debug' => __('Debug (Verbose)', 'wp-breach')
                        ),
                        'default' => 'warnings',
                        'validation' => array(
                            'enum' => array('none', 'errors', 'warnings', 'info', 'debug')
                        )
                    )
                )
            )
        );
    }

    /**
     * Get all settings groups.
     *
     * @since    1.0.0
     * @return   array    Settings groups.
     */
    public function get_settings_groups() {
        return $this->schema;
    }

    /**
     * Get specific settings group.
     *
     * @since    1.0.0
     * @param    string   $group_name    Group name.
     * @return   array                   Group configuration.
     */
    public function get_settings_group($group_name) {
        return isset($this->schema[$group_name]) ? $this->schema[$group_name] : null;
    }

    /**
     * Get settings for a specific group.
     *
     * @since    1.0.0
     * @param    string   $group_name    Group name.
     * @return   array                   Group settings.
     */
    public function get_group_settings($group_name) {
        $group = $this->get_settings_group($group_name);
        return $group ? $group['settings'] : array();
    }

    /**
     * Get default values for a specific group.
     *
     * @since    1.0.0
     * @param    string   $group_name    Group name.
     * @return   array                   Default values.
     */
    public function get_group_defaults($group_name) {
        $settings = $this->get_group_settings($group_name);
        $defaults = array();
        
        foreach ($settings as $setting_name => $setting_config) {
            if (isset($setting_config['default'])) {
                $defaults[$setting_name] = $setting_config['default'];
            }
        }
        
        return $defaults;
    }

    /**
     * Get default value for a specific setting.
     *
     * @since    1.0.0
     * @param    string   $group_name      Group name.
     * @param    string   $setting_name    Setting name.
     * @return   mixed                     Default value.
     */
    public function get_setting_default($group_name, $setting_name) {
        $settings = $this->get_group_settings($group_name);
        
        if (isset($settings[$setting_name]['default'])) {
            return $settings[$setting_name]['default'];
        }
        
        return null;
    }

    /**
     * Get all default values from all groups.
     *
     * @since    1.0.0
     * @return   array    All default values.
     */
    public function get_default_values() {
        $defaults = array();
        
        foreach ($this->schema as $group_name => $group_config) {
            $defaults[$group_name] = $this->get_group_defaults($group_name);
        }
        
        return $defaults;
    }

    /**
     * Get setting configuration.
     *
     * @since    1.0.0
     * @param    string   $group_name      Group name.
     * @param    string   $setting_name    Setting name.
     * @return   array                     Setting configuration.
     */
    public function get_setting_config($group_name, $setting_name) {
        $settings = $this->get_group_settings($group_name);
        return isset($settings[$setting_name]) ? $settings[$setting_name] : null;
    }

    /**
     * Get help text for a setting.
     *
     * @since    1.0.0
     * @param    string   $group_name      Group name.
     * @param    string   $setting_name    Setting name.
     * @return   string                    Help text.
     */
    public function get_setting_help($group_name, $setting_name) {
        $config = $this->get_setting_config($group_name, $setting_name);
        return isset($config['help']) ? $config['help'] : '';
    }

    /**
     * Get permissions for a group.
     *
     * @since    1.0.0
     * @param    string   $group_name    Group name.
     * @return   array                   Permissions array.
     */
    public function get_group_permissions($group_name) {
        $group = $this->get_settings_group($group_name);
        return isset($group['permissions']) ? $group['permissions'] : array();
    }

    /**
     * Get sensitive settings for a group.
     *
     * @since    1.0.0
     * @param    string   $group_name    Group name.
     * @return   array                   Sensitive setting names.
     */
    public function get_sensitive_settings($group_name) {
        $settings = $this->get_group_settings($group_name);
        $sensitive = array();
        
        foreach ($settings as $setting_name => $setting_config) {
            if (!empty($setting_config['sensitive'])) {
                $sensitive[] = $setting_name;
            }
        }
        
        return $sensitive;
    }

    /**
     * Get available languages.
     *
     * @since    1.0.0
     * @access   private
     * @return   array    Available languages.
     */
    private function get_available_languages() {
        return array(
            'en_US' => __('English (US)', 'wp-breach'),
            'en_GB' => __('English (UK)', 'wp-breach'),
            'es_ES' => __('Spanish', 'wp-breach'),
            'fr_FR' => __('French', 'wp-breach'),
            'de_DE' => __('German', 'wp-breach'),
            'it_IT' => __('Italian', 'wp-breach'),
            'pt_BR' => __('Portuguese (Brazil)', 'wp-breach'),
            'ru_RU' => __('Russian', 'wp-breach'),
            'zh_CN' => __('Chinese (Simplified)', 'wp-breach'),
            'ja' => __('Japanese', 'wp-breach')
        );
    }

    /**
     * Get timezone options.
     *
     * @since    1.0.0
     * @access   private
     * @return   array    Timezone options.
     */
    private function get_timezone_options() {
        $timezone_identifiers = timezone_identifiers_list();
        $timezones = array();
        
        foreach ($timezone_identifiers as $timezone) {
            $timezones[$timezone] = $timezone;
        }
        
        return $timezones;
    }

    /**
     * Validate schema structure.
     *
     * @since    1.0.0
     * @return   bool    Schema is valid.
     */
    public function validate_schema() {
        foreach ($this->schema as $group_name => $group_config) {
            // Check required group properties
            if (!isset($group_config['label']) || !isset($group_config['settings'])) {
                return false;
            }
            
            // Check settings structure
            foreach ($group_config['settings'] as $setting_name => $setting_config) {
                if (!isset($setting_config['type']) || !isset($setting_config['label'])) {
                    return false;
                }
            }
        }
        
        return true;
    }

    /**
     * Get settings by type.
     *
     * @since    1.0.0
     * @param    string   $type    Setting type.
     * @return   array             Settings of specified type.
     */
    public function get_settings_by_type($type) {
        $settings_by_type = array();
        
        foreach ($this->schema as $group_name => $group_config) {
            foreach ($group_config['settings'] as $setting_name => $setting_config) {
                if ($setting_config['type'] === $type) {
                    $settings_by_type[] = array(
                        'group' => $group_name,
                        'name' => $setting_name,
                        'config' => $setting_config
                    );
                }
            }
        }
        
        return $settings_by_type;
    }

    /**
     * Check if setting has dependencies.
     *
     * @since    1.0.0
     * @param    string   $group_name      Group name.
     * @param    string   $setting_name    Setting name.
     * @return   bool                      Has dependencies.
     */
    public function setting_has_dependencies($group_name, $setting_name) {
        $config = $this->get_setting_config($group_name, $setting_name);
        return isset($config['dependency']);
    }

    /**
     * Get setting dependencies.
     *
     * @since    1.0.0
     * @param    string   $group_name      Group name.
     * @param    string   $setting_name    Setting name.
     * @return   array                     Dependencies.
     */
    public function get_setting_dependencies($group_name, $setting_name) {
        $config = $this->get_setting_config($group_name, $setting_name);
        return isset($config['dependency']) ? $config['dependency'] : null;
    }
}
