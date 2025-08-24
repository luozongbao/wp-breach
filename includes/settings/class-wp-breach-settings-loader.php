<?php

/**
 * Settings Loader for WP-Breach.
 *
 * This class loads and initializes all settings-related components,
 * orchestrating the settings management system.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/settings
 */

/**
 * The settings loader class.
 *
 * Coordinates loading of all settings components and provides
 * unified access to the settings management system.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/settings
 * @author     WP Breach Team
 */
class WP_Breach_Settings_Loader {

    /**
     * Settings manager instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Settings_Manager    $manager    Settings manager.
     */
    private $manager;

    /**
     * Settings schema instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Settings_Schema     $schema     Settings schema.
     */
    private $schema;

    /**
     * Settings validator instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Settings_Validator  $validator  Settings validator.
     */
    private $validator;

    /**
     * Settings admin interface instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Settings_Admin      $admin      Settings admin.
     */
    private $admin;

    /**
     * Whether settings system is loaded.
     *
     * @since    1.0.0
     * @access   private
     * @var      bool     $loaded    System loaded status.
     */
    private $loaded;

    /**
     * Initialize the settings loader.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->loaded = false;
        $this->load_dependencies();
        $this->init_components();
        $this->init_hooks();
    }

    /**
     * Load required class files.
     *
     * @since    1.0.0
     * @access   private
     */
    private function load_dependencies() {
        // Core settings classes
        require_once WP_BREACH_PLUGIN_PATH . 'includes/settings/class-wp-breach-settings-schema.php';
        require_once WP_BREACH_PLUGIN_PATH . 'includes/settings/class-wp-breach-settings-validator.php';
        require_once WP_BREACH_PLUGIN_PATH . 'includes/settings/class-wp-breach-settings-manager.php';
        
        // Admin interface (only in admin)
        if (is_admin()) {
            require_once WP_BREACH_PLUGIN_PATH . 'admin/class-wp-breach-settings-admin.php';
        }
    }

    /**
     * Initialize all settings components.
     *
     * @since    1.0.0
     * @access   private
     */
    private function init_components() {
        try {
            // Initialize schema first
            $this->schema = new WP_Breach_Settings_Schema();
            
            // Validate schema structure
            if (!$this->schema->validate_schema()) {
                throw new Exception('Invalid settings schema structure');
            }
            
            // Initialize validator with schema
            $this->validator = new WP_Breach_Settings_Validator($this->schema);
            
            // Initialize manager with schema and validator
            $this->manager = new WP_Breach_Settings_Manager($this->schema, $this->validator);
            
            // Initialize admin interface (admin only)
            if (is_admin()) {
                $this->admin = new WP_Breach_Settings_Admin($this->manager, $this->schema, $this->validator);
            }
            
            $this->loaded = true;
            
        } catch (Exception $e) {
            error_log('WP-Breach Settings Loader Error: ' . $e->getMessage());
            $this->loaded = false;
        }
    }

    /**
     * Initialize WordPress hooks.
     *
     * @since    1.0.0
     * @access   private
     */
    private function init_hooks() {
        if (!$this->loaded) {
            return;
        }

        // Plugin activation/deactivation hooks
        register_activation_hook(WP_BREACH_PLUGIN_FILE, array($this, 'on_plugin_activation'));
        register_deactivation_hook(WP_BREACH_PLUGIN_FILE, array($this, 'on_plugin_deactivation'));
        
        // Plugin initialization
        add_action('plugins_loaded', array($this, 'on_plugins_loaded'));
        
        // Settings API integration
        add_action('init', array($this, 'register_settings_api'));
        
        // REST API endpoints
        add_action('rest_api_init', array($this, 'register_rest_endpoints'));
        
        // AJAX endpoints for frontend if needed
        add_action('wp_ajax_wp_breach_get_setting', array($this, 'ajax_get_setting'));
        add_action('wp_ajax_wp_breach_update_setting', array($this, 'ajax_update_setting'));
        
        // Cleanup hooks
        add_action('wp_scheduled_delete', array($this, 'cleanup_old_backups'));
    }

    /**
     * Handle plugin activation.
     *
     * @since    1.0.0
     */
    public function on_plugin_activation() {
        if (!$this->loaded) {
            return;
        }

        // Initialize default settings
        $this->init_default_settings();
        
        // Create settings backup
        $this->manager->create_settings_backup('activation');
        
        // Schedule cleanup tasks
        if (!wp_next_scheduled('wp_breach_settings_cleanup')) {
            wp_schedule_event(time(), 'daily', 'wp_breach_settings_cleanup');
        }
    }

    /**
     * Handle plugin deactivation.
     *
     * @since    1.0.0
     */
    public function on_plugin_deactivation() {
        if (!$this->loaded) {
            return;
        }

        // Create deactivation backup
        $this->manager->create_settings_backup('deactivation');
        
        // Clear scheduled events
        wp_clear_scheduled_hook('wp_breach_settings_cleanup');
    }

    /**
     * Handle plugins loaded event.
     *
     * @since    1.0.0
     */
    public function on_plugins_loaded() {
        if (!$this->loaded) {
            return;
        }

        // Load translations
        load_plugin_textdomain(
            'wp-breach',
            false,
            dirname(dirname(plugin_basename(__FILE__))) . '/languages/'
        );
        
        // Initialize settings caching
        $this->manager->init_caching();
        
        // Validate settings integrity
        $this->validate_settings_integrity();
    }

    /**
     * Register WordPress Settings API integration.
     *
     * @since    1.0.0
     */
    public function register_settings_api() {
        if (!$this->loaded || !is_admin()) {
            return;
        }

        $groups = $this->schema->get_settings_groups();
        
        foreach ($groups as $group_name => $group_config) {
            $option_name = 'wp_breach_settings_' . $group_name;
            
            register_setting(
                $option_name,
                $option_name,
                array(
                    'type' => 'object',
                    'description' => $group_config['label'] ?? $group_name,
                    'sanitize_callback' => array($this->manager, 'sanitize_group_settings'),
                    'default' => $this->schema->get_group_defaults($group_name),
                    'show_in_rest' => false // Keep settings secure by default
                )
            );
        }
    }

    /**
     * Register REST API endpoints.
     *
     * @since    1.0.0
     */
    public function register_rest_endpoints() {
        if (!$this->loaded) {
            return;
        }

        // Settings endpoints (restricted to administrators)
        register_rest_route('wp-breach/v1', '/settings', array(
            'methods' => 'GET',
            'callback' => array($this, 'rest_get_settings'),
            'permission_callback' => array($this, 'rest_permissions_check')
        ));

        register_rest_route('wp-breach/v1', '/settings/(?P<group>[a-zA-Z0-9_-]+)', array(
            'methods' => 'GET',
            'callback' => array($this, 'rest_get_settings_group'),
            'permission_callback' => array($this, 'rest_permissions_check'),
            'args' => array(
                'group' => array(
                    'required' => true,
                    'sanitize_callback' => 'sanitize_text_field'
                )
            )
        ));

        register_rest_route('wp-breach/v1', '/settings/(?P<group>[a-zA-Z0-9_-]+)/(?P<setting>[a-zA-Z0-9_-]+)', array(
            array(
                'methods' => 'GET',
                'callback' => array($this, 'rest_get_setting'),
                'permission_callback' => array($this, 'rest_permissions_check')
            ),
            array(
                'methods' => 'POST',
                'callback' => array($this, 'rest_update_setting'),
                'permission_callback' => array($this, 'rest_permissions_check')
            )
        ));
    }

    /**
     * REST API permission check.
     *
     * @since    1.0.0
     * @return   bool    Has permission.
     */
    public function rest_permissions_check() {
        return current_user_can('manage_options');
    }

    /**
     * REST endpoint: Get all settings.
     *
     * @since    1.0.0
     * @param    WP_REST_Request    $request    Request object.
     * @return   WP_REST_Response               Response object.
     */
    public function rest_get_settings($request) {
        $settings = $this->manager->get_all_settings();
        
        // Remove sensitive settings
        $sanitized = $this->validator->sanitize_for_export($settings);
        
        return rest_ensure_response($sanitized);
    }

    /**
     * REST endpoint: Get settings group.
     *
     * @since    1.0.0
     * @param    WP_REST_Request    $request    Request object.
     * @return   WP_REST_Response               Response object.
     */
    public function rest_get_settings_group($request) {
        $group = $request->get_param('group');
        $settings = $this->manager->get_settings_group($group);
        
        if ($settings === null) {
            return new WP_Error('invalid_group', 'Settings group not found', array('status' => 404));
        }
        
        return rest_ensure_response($settings);
    }

    /**
     * REST endpoint: Get single setting.
     *
     * @since    1.0.0
     * @param    WP_REST_Request    $request    Request object.
     * @return   WP_REST_Response               Response object.
     */
    public function rest_get_setting($request) {
        $group = $request->get_param('group');
        $setting = $request->get_param('setting');
        
        $value = $this->manager->get_setting($group, $setting);
        
        if ($value === null) {
            return new WP_Error('setting_not_found', 'Setting not found', array('status' => 404));
        }
        
        return rest_ensure_response(array('value' => $value));
    }

    /**
     * REST endpoint: Update single setting.
     *
     * @since    1.0.0
     * @param    WP_REST_Request    $request    Request object.
     * @return   WP_REST_Response               Response object.
     */
    public function rest_update_setting($request) {
        $group = $request->get_param('group');
        $setting = $request->get_param('setting');
        $value = $request->get_param('value');
        
        $result = $this->manager->update_setting($group, $setting, $value);
        
        if ($result) {
            return rest_ensure_response(array('success' => true));
        } else {
            return new WP_Error('update_failed', 'Failed to update setting', array('status' => 500));
        }
    }

    /**
     * AJAX handler: Get setting value.
     *
     * @since    1.0.0
     */
    public function ajax_get_setting() {
        check_ajax_referer('wp_breach_settings_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Permission denied');
        }
        
        $group = sanitize_text_field($_POST['group'] ?? '');
        $setting = sanitize_text_field($_POST['setting'] ?? '');
        
        $value = $this->manager->get_setting($group, $setting);
        
        wp_send_json_success(array('value' => $value));
    }

    /**
     * AJAX handler: Update setting value.
     *
     * @since    1.0.0
     */
    public function ajax_update_setting() {
        check_ajax_referer('wp_breach_settings_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Permission denied');
        }
        
        $group = sanitize_text_field($_POST['group'] ?? '');
        $setting = sanitize_text_field($_POST['setting'] ?? '');
        $value = $_POST['value'] ?? '';
        
        $result = $this->manager->update_setting($group, $setting, $value);
        
        if ($result) {
            wp_send_json_success();
        } else {
            wp_send_json_error('Update failed');
        }
    }

    /**
     * Initialize default settings on first run.
     *
     * @since    1.0.0
     * @access   private
     */
    private function init_default_settings() {
        $defaults = $this->schema->get_default_values();
        
        foreach ($defaults as $group_name => $group_defaults) {
            $existing = $this->manager->get_settings_group($group_name);
            
            if (empty($existing)) {
                foreach ($group_defaults as $setting_name => $default_value) {
                    $this->manager->update_setting($group_name, $setting_name, $default_value);
                }
            }
        }
    }

    /**
     * Validate settings integrity.
     *
     * @since    1.0.0
     * @access   private
     */
    private function validate_settings_integrity() {
        $all_settings = $this->manager->get_all_settings();
        $validated = $this->validator->validate_all_settings($all_settings);
        
        // Check for validation errors
        if ($this->validator->has_errors()) {
            $errors = $this->validator->get_errors();
            error_log('WP-Breach Settings Validation Errors: ' . print_r($errors, true));
            
            // Optionally reset invalid settings to defaults
            $this->fix_invalid_settings($errors);
        }
    }

    /**
     * Fix invalid settings by resetting to defaults.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $errors    Validation errors.
     */
    private function fix_invalid_settings($errors) {
        foreach ($errors as $field => $field_errors) {
            // Parse field name to get group and setting
            if (preg_match('/^([^.]+)\.(.+)$/', $field, $matches)) {
                $group = $matches[1];
                $setting = $matches[2];
                
                $default = $this->schema->get_setting_default($group, $setting);
                
                if ($default !== null) {
                    $this->manager->update_setting($group, $setting, $default);
                    error_log("Reset invalid setting {$group}.{$setting} to default value");
                }
            }
        }
    }

    /**
     * Cleanup old backup files.
     *
     * @since    1.0.0
     */
    public function cleanup_old_backups() {
        if (!$this->loaded) {
            return;
        }

        $this->manager->cleanup_old_backups();
    }

    /**
     * Get settings manager instance.
     *
     * @since    1.0.0
     * @return   WP_Breach_Settings_Manager|null    Manager instance.
     */
    public function get_manager() {
        return $this->loaded ? $this->manager : null;
    }

    /**
     * Get settings schema instance.
     *
     * @since    1.0.0
     * @return   WP_Breach_Settings_Schema|null     Schema instance.
     */
    public function get_schema() {
        return $this->loaded ? $this->schema : null;
    }

    /**
     * Get settings validator instance.
     *
     * @since    1.0.0
     * @return   WP_Breach_Settings_Validator|null  Validator instance.
     */
    public function get_validator() {
        return $this->loaded ? $this->validator : null;
    }

    /**
     * Get settings admin instance.
     *
     * @since    1.0.0
     * @return   WP_Breach_Settings_Admin|null      Admin instance.
     */
    public function get_admin() {
        return $this->loaded ? $this->admin : null;
    }

    /**
     * Check if settings system is loaded successfully.
     *
     * @since    1.0.0
     * @return   bool    Is loaded.
     */
    public function is_loaded() {
        return $this->loaded;
    }

    /**
     * Get a setting value (convenience method).
     *
     * @since    1.0.0
     * @param    string   $group      Group name.
     * @param    string   $setting    Setting name.
     * @param    mixed    $default    Default value if setting not found.
     * @return   mixed                Setting value.
     */
    public function get_setting($group, $setting, $default = null) {
        if (!$this->loaded) {
            return $default;
        }
        
        $value = $this->manager->get_setting($group, $setting);
        return $value !== null ? $value : $default;
    }

    /**
     * Update a setting value (convenience method).
     *
     * @since    1.0.0
     * @param    string   $group      Group name.
     * @param    string   $setting    Setting name.
     * @param    mixed    $value      Setting value.
     * @return   bool                 Success status.
     */
    public function update_setting($group, $setting, $value) {
        if (!$this->loaded) {
            return false;
        }
        
        return $this->manager->update_setting($group, $setting, $value);
    }
}
