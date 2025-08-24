<?php

/**
 * Settings Manager for WP-Breach.
 *
 * This class handles all settings operations including storage, retrieval,
 * validation, caching, and advanced configuration management.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/settings
 */

/**
 * The settings manager class.
 *
 * Provides centralized management of all plugin settings with advanced
 * features like caching, validation, import/export, and user permissions.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/settings
 * @author     WP Breach Team
 */
class WP_Breach_Settings_Manager {

    /**
     * Settings cache.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $cache    Settings cache array.
     */
    private $cache;

    /**
     * Settings schema.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Settings_Schema    $schema    Settings schema instance.
     */
    private $schema;

    /**
     * Settings validator.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Settings_Validator    $validator    Settings validator instance.
     */
    private $validator;

    /**
     * Settings option prefix.
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $option_prefix    WordPress option prefix.
     */
    private $option_prefix;

    /**
     * Default settings.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $defaults    Default settings values.
     */
    private $defaults;

    /**
     * Initialize the settings manager.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->option_prefix = 'wp_breach_';
        $this->cache = array();
        $this->schema = new WP_Breach_Settings_Schema();
        $this->validator = new WP_Breach_Settings_Validator();
        $this->defaults = $this->schema->get_default_values();
        
        // Initialize settings if not exists
        $this->initialize_settings();
        
        // Register hooks
        $this->register_hooks();
    }

    /**
     * Register WordPress hooks.
     *
     * @since    1.0.0
     * @access   private
     */
    private function register_hooks() {
        add_action('admin_init', array($this, 'register_settings'));
        add_action('wp_breach_settings_updated', array($this, 'clear_cache'));
        add_action('wp_breach_daily_cleanup', array($this, 'cleanup_expired_cache'));
    }

    /**
     * Initialize default settings if they don't exist.
     *
     * @since    1.0.0
     * @access   private
     */
    private function initialize_settings() {
        $groups = $this->schema->get_settings_groups();
        
        foreach ($groups as $group_name => $group_config) {
            $option_name = $this->option_prefix . $group_name;
            
            if (false === get_option($option_name)) {
                $default_values = $this->schema->get_group_defaults($group_name);
                update_option($option_name, $default_values);
            }
        }
    }

    /**
     * Register settings with WordPress.
     *
     * @since    1.0.0
     */
    public function register_settings() {
        $groups = $this->schema->get_settings_groups();
        
        foreach ($groups as $group_name => $group_config) {
            $option_name = $this->option_prefix . $group_name;
            
            register_setting(
                'wp_breach_' . $group_name . '_group',
                $option_name,
                array(
                    'type' => 'array',
                    'sanitize_callback' => array($this, 'sanitize_settings_group'),
                    'default' => $this->schema->get_group_defaults($group_name)
                )
            );
        }
    }

    /**
     * Get a specific setting value.
     *
     * @since    1.0.0
     * @param    string   $key        Setting key in format 'group.setting'.
     * @param    mixed    $default    Default value if setting not found.
     * @return   mixed                Setting value.
     */
    public function get_setting($key, $default = null) {
        $parts = explode('.', $key, 2);
        
        if (count($parts) !== 2) {
            return $default;
        }
        
        list($group, $setting) = $parts;
        
        // Check cache first
        $cache_key = $group . '_' . $setting;
        if (isset($this->cache[$cache_key])) {
            return $this->cache[$cache_key];
        }
        
        // Get group settings
        $group_settings = $this->get_settings_group($group);
        
        $value = isset($group_settings[$setting]) ? $group_settings[$setting] : $default;
        
        // If no value found, try to get default from schema
        if ($value === null) {
            $schema_default = $this->schema->get_setting_default($group, $setting);
            $value = $schema_default !== null ? $schema_default : $default;
        }
        
        // Cache the value
        $this->cache[$cache_key] = $value;
        
        return $value;
    }

    /**
     * Update a specific setting value.
     *
     * @since    1.0.0
     * @param    string   $key      Setting key in format 'group.setting'.
     * @param    mixed    $value    New setting value.
     * @return   bool               Success status.
     */
    public function update_setting($key, $value) {
        $parts = explode('.', $key, 2);
        
        if (count($parts) !== 2) {
            return false;
        }
        
        list($group, $setting) = $parts;
        
        // Validate the setting
        $validation_result = $this->validator->validate_setting($group, $setting, $value);
        if (!$validation_result['valid']) {
            return false;
        }
        
        // Get current group settings
        $group_settings = $this->get_settings_group($group);
        $old_value = isset($group_settings[$setting]) ? $group_settings[$setting] : null;
        
        // Update the setting
        $group_settings[$setting] = $validation_result['sanitized_value'];
        
        // Save the group
        $result = $this->update_settings_group($group, $group_settings);
        
        if ($result) {
            // Clear cache
            $cache_key = $group . '_' . $setting;
            unset($this->cache[$cache_key]);
            
            // Fire action hook
            do_action('wp_breach_setting_updated', $key, $value, $old_value);
        }
        
        return $result;
    }

    /**
     * Get all settings for a specific group.
     *
     * @since    1.0.0
     * @param    string   $group_name    Settings group name.
     * @return   array                   Group settings array.
     */
    public function get_settings_group($group_name) {
        // Check cache first
        if (isset($this->cache['group_' . $group_name])) {
            return $this->cache['group_' . $group_name];
        }
        
        $option_name = $this->option_prefix . $group_name;
        $settings = get_option($option_name, array());
        
        // Merge with defaults to ensure all settings exist
        $defaults = $this->schema->get_group_defaults($group_name);
        $settings = wp_parse_args($settings, $defaults);
        
        // Cache the group
        $this->cache['group_' . $group_name] = $settings;
        
        return $settings;
    }

    /**
     * Update settings for a specific group.
     *
     * @since    1.0.0
     * @param    string   $group_name    Settings group name.
     * @param    array    $settings      New settings array.
     * @return   bool                    Success status.
     */
    public function update_settings_group($group_name, $settings) {
        // Validate the entire group
        $validation_result = $this->validator->validate_settings_group($group_name, $settings);
        
        if (!$validation_result['valid']) {
            return false;
        }
        
        $option_name = $this->option_prefix . $group_name;
        $old_settings = $this->get_settings_group($group_name);
        
        // Update the option
        $result = update_option($option_name, $validation_result['sanitized_values']);
        
        if ($result) {
            // Clear cache
            unset($this->cache['group_' . $group_name]);
            $this->clear_group_cache($group_name);
            
            // Fire action hook
            do_action('wp_breach_settings_group_updated', $group_name, $settings, $old_settings);
            do_action('wp_breach_settings_updated');
        }
        
        return $result;
    }

    /**
     * Get all settings from all groups.
     *
     * @since    1.0.0
     * @return   array    All settings organized by group.
     */
    public function get_all_settings() {
        $all_settings = array();
        $groups = $this->schema->get_settings_groups();
        
        foreach ($groups as $group_name => $group_config) {
            $all_settings[$group_name] = $this->get_settings_group($group_name);
        }
        
        return $all_settings;
    }

    /**
     * Reset settings to defaults.
     *
     * @since    1.0.0
     * @param    string   $group_name    Optional. Specific group to reset.
     * @return   bool                    Success status.
     */
    public function reset_to_defaults($group_name = null) {
        if ($group_name) {
            // Reset specific group
            $defaults = $this->schema->get_group_defaults($group_name);
            return $this->update_settings_group($group_name, $defaults);
        } else {
            // Reset all groups
            $groups = $this->schema->get_settings_groups();
            $success = true;
            
            foreach ($groups as $group => $config) {
                $defaults = $this->schema->get_group_defaults($group);
                if (!$this->update_settings_group($group, $defaults)) {
                    $success = false;
                }
            }
            
            if ($success) {
                $this->clear_cache();
                do_action('wp_breach_settings_reset');
            }
            
            return $success;
        }
    }

    /**
     * Export settings configuration.
     *
     * @since    1.0.0
     * @param    array    $groups        Optional. Specific groups to export.
     * @param    array    $options       Export options.
     * @return   array                   Exported settings data.
     */
    public function export_settings($groups = null, $options = array()) {
        $export_options = wp_parse_args($options, array(
            'include_metadata' => true,
            'exclude_sensitive' => true,
            'format' => 'array'
        ));
        
        $export_data = array();
        
        // Add metadata
        if ($export_options['include_metadata']) {
            $export_data['metadata'] = array(
                'version' => WP_BREACH_VERSION,
                'exported_at' => current_time('mysql'),
                'site_url' => get_site_url(),
                'wp_version' => get_bloginfo('version')
            );
        }
        
        // Export settings
        if ($groups === null) {
            $groups = array_keys($this->schema->get_settings_groups());
        }
        
        $export_data['settings'] = array();
        
        foreach ($groups as $group_name) {
            $group_settings = $this->get_settings_group($group_name);
            
            // Filter sensitive settings if requested
            if ($export_options['exclude_sensitive']) {
                $group_settings = $this->filter_sensitive_settings($group_name, $group_settings);
            }
            
            $export_data['settings'][$group_name] = $group_settings;
        }
        
        // Format the output
        switch ($export_options['format']) {
            case 'json':
                return json_encode($export_data, JSON_PRETTY_PRINT);
            case 'serialized':
                return serialize($export_data);
            default:
                return $export_data;
        }
    }

    /**
     * Import settings configuration.
     *
     * @since    1.0.0
     * @param    mixed    $settings_data    Settings data to import.
     * @param    array    $options          Import options.
     * @return   array                      Import result.
     */
    public function import_settings($settings_data, $options = array()) {
        $import_options = wp_parse_args($options, array(
            'validate' => true,
            'backup_current' => true,
            'override_existing' => true,
            'skip_on_error' => false
        ));
        
        try {
            // Parse settings data based on format
            $parsed_data = $this->parse_import_data($settings_data);
            
            if (!isset($parsed_data['settings'])) {
                return array(
                    'success' => false,
                    'error' => 'Invalid import data format'
                );
            }
            
            // Backup current settings if requested
            $backup_id = null;
            if ($import_options['backup_current']) {
                $backup_id = $this->create_settings_backup();
            }
            
            $imported_groups = array();
            $errors = array();
            
            foreach ($parsed_data['settings'] as $group_name => $group_settings) {
                try {
                    // Validate group if requested
                    if ($import_options['validate']) {
                        $validation_result = $this->validator->validate_settings_group($group_name, $group_settings);
                        
                        if (!$validation_result['valid']) {
                            $errors[$group_name] = $validation_result['errors'];
                            
                            if ($import_options['skip_on_error']) {
                                continue;
                            } else {
                                throw new Exception('Validation failed for group: ' . $group_name);
                            }
                        }
                        
                        $group_settings = $validation_result['sanitized_values'];
                    }
                    
                    // Merge or override settings
                    if (!$import_options['override_existing']) {
                        $current_settings = $this->get_settings_group($group_name);
                        $group_settings = wp_parse_args($group_settings, $current_settings);
                    }
                    
                    // Import the group
                    if ($this->update_settings_group($group_name, $group_settings)) {
                        $imported_groups[] = $group_name;
                    } else {
                        $errors[$group_name] = 'Failed to update settings group';
                    }
                    
                } catch (Exception $e) {
                    $errors[$group_name] = $e->getMessage();
                    
                    if (!$import_options['skip_on_error']) {
                        // Restore backup if import fails
                        if ($backup_id) {
                            $this->restore_settings_backup($backup_id);
                        }
                        
                        return array(
                            'success' => false,
                            'error' => $e->getMessage(),
                            'backup_id' => $backup_id
                        );
                    }
                }
            }
            
            $success = !empty($imported_groups);
            
            if ($success) {
                do_action('wp_breach_settings_imported', $imported_groups, $parsed_data);
            }
            
            return array(
                'success' => $success,
                'imported_groups' => $imported_groups,
                'errors' => $errors,
                'backup_id' => $backup_id
            );
            
        } catch (Exception $e) {
            return array(
                'success' => false,
                'error' => $e->getMessage()
            );
        }
    }

    /**
     * Create a backup of current settings.
     *
     * @since    1.0.0
     * @return   string    Backup ID.
     */
    public function create_settings_backup() {
        $backup_id = 'backup_' . date('Y_m_d_H_i_s') . '_' . wp_generate_password(8, false);
        $all_settings = $this->get_all_settings();
        
        $backup_data = array(
            'id' => $backup_id,
            'created_at' => current_time('mysql'),
            'version' => WP_BREACH_VERSION,
            'settings' => $all_settings
        );
        
        $backups = get_option('wp_breach_settings_backups', array());
        $backups[$backup_id] = $backup_data;
        
        // Keep only last 10 backups
        if (count($backups) > 10) {
            $backup_keys = array_keys($backups);
            $oldest_key = array_shift($backup_keys);
            unset($backups[$oldest_key]);
        }
        
        update_option('wp_breach_settings_backups', $backups);
        
        return $backup_id;
    }

    /**
     * Restore settings from backup.
     *
     * @since    1.0.0
     * @param    string   $backup_id    Backup ID to restore.
     * @return   bool                   Success status.
     */
    public function restore_settings_backup($backup_id) {
        $backups = get_option('wp_breach_settings_backups', array());
        
        if (!isset($backups[$backup_id])) {
            return false;
        }
        
        $backup_data = $backups[$backup_id];
        $backup_settings = $backup_data['settings'];
        
        $success = true;
        
        foreach ($backup_settings as $group_name => $group_settings) {
            if (!$this->update_settings_group($group_name, $group_settings)) {
                $success = false;
            }
        }
        
        if ($success) {
            do_action('wp_breach_settings_restored', $backup_id, $backup_data);
        }
        
        return $success;
    }

    /**
     * Get list of available backups.
     *
     * @since    1.0.0
     * @return   array    List of backups.
     */
    public function get_settings_backups() {
        $backups = get_option('wp_breach_settings_backups', array());
        
        // Return metadata only
        $backup_list = array();
        foreach ($backups as $backup_id => $backup_data) {
            $backup_list[$backup_id] = array(
                'id' => $backup_id,
                'created_at' => $backup_data['created_at'],
                'version' => $backup_data['version']
            );
        }
        
        return $backup_list;
    }

    /**
     * Check if user has permission to access settings.
     *
     * @since    1.0.0
     * @param    string   $group_name    Settings group name.
     * @param    string   $action        Action to check (read, write).
     * @return   bool                    Permission status.
     */
    public function user_can_access_settings($group_name = null, $action = 'read') {
        // Basic capability check
        if (!current_user_can('manage_options')) {
            return false;
        }
        
        // Check group-specific permissions
        if ($group_name) {
            $group_permissions = $this->schema->get_group_permissions($group_name);
            
            if (!empty($group_permissions[$action])) {
                return current_user_can($group_permissions[$action]);
            }
        }
        
        // Default to manage_options for all operations
        return true;
    }

    /**
     * Sanitize settings group data.
     *
     * @since    1.0.0
     * @param    array    $settings    Settings array to sanitize.
     * @return   array                 Sanitized settings.
     */
    public function sanitize_settings_group($settings) {
        // This is called by WordPress Settings API
        // We'll delegate to our validator
        $current_filter = current_filter();
        
        // Extract group name from the filter
        if (preg_match('/sanitize_option_wp_breach_(.+)/', $current_filter, $matches)) {
            $group_name = $matches[1];
            
            $validation_result = $this->validator->validate_settings_group($group_name, $settings);
            
            if ($validation_result['valid']) {
                return $validation_result['sanitized_values'];
            } else {
                // Log validation errors
                error_log('WP-Breach Settings Validation Error: ' . json_encode($validation_result['errors']));
                
                // Return current values to prevent data loss
                return $this->get_settings_group($group_name);
            }
        }
        
        return $settings;
    }

    /**
     * Clear settings cache.
     *
     * @since    1.0.0
     * @param    string   $group_name    Optional. Specific group to clear.
     */
    public function clear_cache($group_name = null) {
        if ($group_name) {
            $this->clear_group_cache($group_name);
        } else {
            $this->cache = array();
        }
        
        // Clear any transients
        delete_transient('wp_breach_settings_cache');
    }

    /**
     * Clear cache for specific group.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $group_name    Group name to clear.
     */
    private function clear_group_cache($group_name) {
        // Clear group cache
        unset($this->cache['group_' . $group_name]);
        
        // Clear individual setting caches for this group
        $group_settings = $this->schema->get_group_settings($group_name);
        
        if ($group_settings) {
            foreach (array_keys($group_settings) as $setting_name) {
                $cache_key = $group_name . '_' . $setting_name;
                unset($this->cache[$cache_key]);
            }
        }
    }

    /**
     * Parse import data from various formats.
     *
     * @since    1.0.0
     * @access   private
     * @param    mixed    $data    Data to parse.
     * @return   array             Parsed data.
     */
    private function parse_import_data($data) {
        if (is_array($data)) {
            return $data;
        }
        
        if (is_string($data)) {
            // Try JSON first
            $json_data = json_decode($data, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                return $json_data;
            }
            
            // Try serialized data
            $unserialized = @unserialize($data);
            if ($unserialized !== false) {
                return $unserialized;
            }
        }
        
        throw new Exception('Unable to parse import data format');
    }

    /**
     * Filter sensitive settings from export.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $group_name       Group name.
     * @param    array    $group_settings   Group settings.
     * @return   array                      Filtered settings.
     */
    private function filter_sensitive_settings($group_name, $group_settings) {
        $sensitive_settings = $this->schema->get_sensitive_settings($group_name);
        
        foreach ($sensitive_settings as $setting_name) {
            if (isset($group_settings[$setting_name])) {
                $group_settings[$setting_name] = '[FILTERED]';
            }
        }
        
        return $group_settings;
    }

    /**
     * Cleanup expired cache entries.
     *
     * @since    1.0.0
     */
    public function cleanup_expired_cache() {
        // This method can be extended to handle cache expiration
        // For now, we'll just clear the cache periodically
        $this->clear_cache();
    }

    /**
     * Get settings statistics.
     *
     * @since    1.0.0
     * @return   array    Settings statistics.
     */
    public function get_settings_statistics() {
        $stats = array(
            'total_groups' => 0,
            'total_settings' => 0,
            'modified_from_defaults' => 0,
            'last_modified' => null
        );
        
        $groups = $this->schema->get_settings_groups();
        $stats['total_groups'] = count($groups);
        
        foreach ($groups as $group_name => $group_config) {
            $group_settings = $this->get_settings_group($group_name);
            $group_defaults = $this->schema->get_group_defaults($group_name);
            
            $stats['total_settings'] += count($group_settings);
            
            // Check for modifications
            foreach ($group_settings as $setting_name => $value) {
                $default_value = isset($group_defaults[$setting_name]) ? $group_defaults[$setting_name] : null;
                
                if ($value !== $default_value) {
                    $stats['modified_from_defaults']++;
                }
            }
        }
        
        return $stats;
    }

    /**
     * Validate settings dependencies.
     *
     * @since    1.0.0
     * @param    array    $settings    Settings to validate.
     * @return   array                 Validation result.
     */
    public function validate_dependencies($settings) {
        return $this->validator->validate_dependencies($settings);
    }

    /**
     * Get setting help text.
     *
     * @since    1.0.0
     * @param    string   $group_name      Group name.
     * @param    string   $setting_name    Setting name.
     * @return   string                    Help text.
     */
    public function get_setting_help($group_name, $setting_name) {
        return $this->schema->get_setting_help($group_name, $setting_name);
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
        return $this->schema->get_setting_config($group_name, $setting_name);
    }
}
