<?php

/**
 * Admin Settings Interface for WP-Breach.
 *
 * This class handles the admin interface for plugin settings,
 * including forms, validation, and user interactions.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/admin/settings
 */

/**
 * The admin settings interface class.
 *
 * Provides the complete admin interface for settings management
 * with tabbed navigation, form handling, and user-friendly controls.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/admin/settings
 * @author     WP Breach Team
 */
class WP_Breach_Settings_Admin {

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
     * Current active tab.
     *
     * @since    1.0.0
     * @access   private
     * @var      string    $active_tab    Current active tab.
     */
    private $active_tab;

    /**
     * Form notices and messages.
     *
     * @since    1.0.0
     * @access   private
     * @var      array     $notices       Form notices.
     */
    private $notices;

    /**
     * Initialize the admin settings interface.
     *
     * @since    1.0.0
     * @param    WP_Breach_Settings_Manager    $manager     Settings manager.
     * @param    WP_Breach_Settings_Schema     $schema      Settings schema.
     * @param    WP_Breach_Settings_Validator  $validator   Settings validator.
     */
    public function __construct($manager, $schema, $validator) {
        $this->manager = $manager;
        $this->schema = $schema;
        $this->validator = $validator;
        $this->notices = array();
        
        $this->determine_active_tab();
        $this->init_hooks();
    }

    /**
     * Initialize WordPress hooks.
     *
     * @since    1.0.0
     * @access   private
     */
    private function init_hooks() {
        add_action('admin_menu', array($this, 'add_settings_page'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        add_action('wp_ajax_wp_breach_settings_import', array($this, 'handle_settings_import'));
        add_action('wp_ajax_wp_breach_settings_export', array($this, 'handle_settings_export'));
        add_action('wp_ajax_wp_breach_settings_reset', array($this, 'handle_settings_reset'));
    }

    /**
     * Add settings page to admin menu.
     *
     * @since    1.0.0
     */
    public function add_settings_page() {
        add_submenu_page(
            'wp-breach',
            __('Settings', 'wp-breach'),
            __('Settings', 'wp-breach'),
            'manage_options',
            'wp-breach-settings',
            array($this, 'render_settings_page')
        );
    }

    /**
     * Register WordPress settings.
     *
     * @since    1.0.0
     */
    public function register_settings() {
        $groups = $this->schema->get_settings_groups();
        
        foreach ($groups as $group_name => $group_config) {
            register_setting(
                'wp_breach_settings_' . $group_name,
                'wp_breach_settings_' . $group_name,
                array(
                    'sanitize_callback' => array($this, 'sanitize_settings_group'),
                    'default' => $this->schema->get_group_defaults($group_name)
                )
            );
        }
    }

    /**
     * Enqueue admin scripts and styles.
     *
     * @since    1.0.0
     * @param    string   $hook_suffix    Current admin page hook.
     */
    public function enqueue_admin_scripts($hook_suffix) {
        if (strpos($hook_suffix, 'wp-breach-settings') === false) {
            return;
        }

        wp_enqueue_style(
            'wp-breach-settings-admin',
            WP_BREACH_PLUGIN_URL . 'admin/css/settings-admin.css',
            array(),
            WP_BREACH_VERSION
        );

        wp_enqueue_script(
            'wp-breach-settings-admin',
            WP_BREACH_PLUGIN_URL . 'admin/js/settings-admin.js',
            array('jquery', 'wp-util'),
            WP_BREACH_VERSION,
            true
        );

        wp_localize_script('wp-breach-settings-admin', 'wpBreachSettings', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('wp_breach_settings_nonce'),
            'strings' => array(
                'confirmReset' => __('Are you sure you want to reset all settings to their default values? This action cannot be undone.', 'wp-breach'),
                'confirmImport' => __('Importing settings will overwrite current configuration. Continue?', 'wp-breach'),
                'exportSuccess' => __('Settings exported successfully.', 'wp-breach'),
                'importSuccess' => __('Settings imported successfully.', 'wp-breach'),
                'resetSuccess' => __('Settings reset to defaults successfully.', 'wp-breach'),
                'error' => __('An error occurred. Please try again.', 'wp-breach')
            )
        ));
    }

    /**
     * Render the main settings page.
     *
     * @since    1.0.0
     */
    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'wp-breach'));
        }

        $this->handle_form_submission();
        ?>
        <div class="wrap wp-breach-settings">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            
            <?php $this->render_notices(); ?>
            
            <div class="wp-breach-settings-container">
                <?php $this->render_settings_tabs(); ?>
                
                <div class="wp-breach-settings-content">
                    <?php $this->render_settings_form(); ?>
                </div>
                
                <div class="wp-breach-settings-sidebar">
                    <?php $this->render_settings_sidebar(); ?>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Render settings navigation tabs.
     *
     * @since    1.0.0
     * @access   private
     */
    private function render_settings_tabs() {
        $groups = $this->schema->get_settings_groups();
        $sorted_groups = $this->sort_groups_by_priority($groups);
        ?>
        <nav class="nav-tab-wrapper wp-breach-nav-tabs">
            <?php foreach ($sorted_groups as $group_name => $group_config): ?>
                <a href="<?php echo esc_url(add_query_arg('tab', $group_name, admin_url('admin.php?page=wp-breach-settings'))); ?>"
                   class="nav-tab <?php echo $this->active_tab === $group_name ? 'nav-tab-active' : ''; ?>">
                    <?php if (isset($group_config['icon'])): ?>
                        <span class="dashicons dashicons-<?php echo esc_attr($group_config['icon']); ?>"></span>
                    <?php endif; ?>
                    <?php echo esc_html($group_config['label']); ?>
                </a>
            <?php endforeach; ?>
        </nav>
        <?php
    }

    /**
     * Render settings form for active tab.
     *
     * @since    1.0.0
     * @access   private
     */
    private function render_settings_form() {
        $group_config = $this->schema->get_settings_group($this->active_tab);
        
        if (!$group_config) {
            echo '<div class="notice notice-error"><p>' . __('Invalid settings group.', 'wp-breach') . '</p></div>';
            return;
        }

        $current_values = $this->manager->get_settings_group($this->active_tab);
        ?>
        <div class="wp-breach-settings-tab-content" id="tab-<?php echo esc_attr($this->active_tab); ?>">
            <div class="settings-group-header">
                <h2><?php echo esc_html($group_config['label']); ?></h2>
                <?php if (isset($group_config['description'])): ?>
                    <p class="description"><?php echo esc_html($group_config['description']); ?></p>
                <?php endif; ?>
            </div>

            <form method="post" action="" class="wp-breach-settings-form">
                <?php wp_nonce_field('wp_breach_settings_save', 'wp_breach_settings_nonce'); ?>
                <input type="hidden" name="action" value="save_settings">
                <input type="hidden" name="settings_group" value="<?php echo esc_attr($this->active_tab); ?>">

                <table class="form-table wp-breach-form-table" role="presentation">
                    <tbody>
                        <?php $this->render_settings_fields($group_config['settings'], $current_values); ?>
                    </tbody>
                </table>

                <div class="submit-section">
                    <?php submit_button(__('Save Settings', 'wp-breach'), 'primary', 'submit', false); ?>
                    <button type="button" class="button button-secondary wp-breach-reset-group" 
                            data-group="<?php echo esc_attr($this->active_tab); ?>">
                        <?php _e('Reset to Defaults', 'wp-breach'); ?>
                    </button>
                </div>
            </form>
        </div>
        <?php
    }

    /**
     * Render individual setting fields.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $settings    Settings configuration.
     * @param    array    $values      Current values.
     */
    private function render_settings_fields($settings, $values) {
        foreach ($settings as $setting_name => $setting_config) {
            $field_name = "wp_breach_settings_{$this->active_tab}[{$setting_name}]";
            $field_id = "wp_breach_setting_{$this->active_tab}_{$setting_name}";
            $current_value = isset($values[$setting_name]) ? $values[$setting_name] : 
                            (isset($setting_config['default']) ? $setting_config['default'] : '');
            
            echo '<tr>';
            echo '<th scope="row">';
            echo '<label for="' . esc_attr($field_id) . '">' . esc_html($setting_config['label']) . '</label>';
            echo '</th>';
            echo '<td>';
            
            $this->render_field($setting_config, $field_name, $field_id, $current_value);
            
            if (isset($setting_config['description'])) {
                echo '<p class="description">' . esc_html($setting_config['description']) . '</p>';
            }
            
            if (isset($setting_config['help'])) {
                echo '<div class="wp-breach-help-text">';
                echo '<span class="dashicons dashicons-editor-help"></span>';
                echo '<div class="help-content">' . esc_html($setting_config['help']) . '</div>';
                echo '</div>';
            }
            
            echo '</td>';
            echo '</tr>';
        }
    }

    /**
     * Render individual field based on type.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $config    Field configuration.
     * @param    string   $name      Field name.
     * @param    string   $id        Field ID.
     * @param    mixed    $value     Current value.
     */
    private function render_field($config, $name, $id, $value) {
        $type = $config['type'];
        $attributes = $this->get_field_attributes($config);
        
        switch ($type) {
            case 'text':
            case 'email':
            case 'url':
                echo '<input type="' . esc_attr($type) . '" name="' . esc_attr($name) . '" id="' . esc_attr($id) . '"';
                echo ' value="' . esc_attr($value) . '"' . $attributes . ' class="regular-text" />';
                break;
                
            case 'textarea':
                $rows = isset($config['rows']) ? $config['rows'] : 4;
                echo '<textarea name="' . esc_attr($name) . '" id="' . esc_attr($id) . '"';
                echo ' rows="' . esc_attr($rows) . '"' . $attributes . ' class="large-text">';
                echo esc_textarea($value);
                echo '</textarea>';
                break;
                
            case 'number':
            case 'range':
                echo '<input type="' . esc_attr($type) . '" name="' . esc_attr($name) . '" id="' . esc_attr($id) . '"';
                echo ' value="' . esc_attr($value) . '"' . $attributes . ' />';
                if ($type === 'range') {
                    echo '<span class="range-value">' . esc_html($value) . '</span>';
                }
                break;
                
            case 'checkbox':
                echo '<label for="' . esc_attr($id) . '">';
                echo '<input type="checkbox" name="' . esc_attr($name) . '" id="' . esc_attr($id) . '"';
                echo ' value="1"' . checked($value, 1, false) . $attributes . ' /> ';
                echo isset($config['checkbox_label']) ? esc_html($config['checkbox_label']) : __('Enable', 'wp-breach');
                echo '</label>';
                break;
                
            case 'select':
                echo '<select name="' . esc_attr($name) . '" id="' . esc_attr($id) . '"' . $attributes . '>';
                if (isset($config['options'])) {
                    foreach ($config['options'] as $option_value => $option_label) {
                        echo '<option value="' . esc_attr($option_value) . '"';
                        echo selected($value, $option_value, false) . '>';
                        echo esc_html($option_label);
                        echo '</option>';
                    }
                }
                echo '</select>';
                break;
                
            case 'multiselect':
                echo '<select name="' . esc_attr($name) . '[]" id="' . esc_attr($id) . '"';
                echo ' multiple="multiple" size="5"' . $attributes . '>';
                if (isset($config['options'])) {
                    $selected_values = is_array($value) ? $value : array();
                    foreach ($config['options'] as $option_value => $option_label) {
                        echo '<option value="' . esc_attr($option_value) . '"';
                        echo in_array($option_value, $selected_values, true) ? ' selected="selected"' : '';
                        echo '>' . esc_html($option_label) . '</option>';
                    }
                }
                echo '</select>';
                break;
                
            case 'time':
                echo '<input type="time" name="' . esc_attr($name) . '" id="' . esc_attr($id) . '"';
                echo ' value="' . esc_attr($value) . '"' . $attributes . ' />';
                break;
                
            case 'date':
                echo '<input type="date" name="' . esc_attr($name) . '" id="' . esc_attr($id) . '"';
                echo ' value="' . esc_attr($value) . '"' . $attributes . ' />';
                break;
                
            case 'color':
                echo '<input type="color" name="' . esc_attr($name) . '" id="' . esc_attr($id) . '"';
                echo ' value="' . esc_attr($value) . '"' . $attributes . ' />';
                break;
                
            default:
                do_action('wp_breach_render_custom_field', $config, $name, $id, $value);
                break;
        }
    }

    /**
     * Get field attributes from configuration.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $config    Field configuration.
     * @return   string              HTML attributes.
     */
    private function get_field_attributes($config) {
        $attributes = array();
        
        $attr_map = array(
            'min' => 'min',
            'max' => 'max',
            'step' => 'step',
            'maxlength' => 'maxlength',
            'placeholder' => 'placeholder',
            'pattern' => 'pattern'
        );
        
        foreach ($attr_map as $config_key => $attr_name) {
            if (isset($config[$config_key])) {
                $attributes[] = $attr_name . '="' . esc_attr($config[$config_key]) . '"';
            }
        }
        
        if (isset($config['validation']['required']) && $config['validation']['required']) {
            $attributes[] = 'required="required"';
        }
        
        if (isset($config['dependency'])) {
            $attributes[] = 'data-dependency="' . esc_attr(json_encode($config['dependency'])) . '"';
        }
        
        return !empty($attributes) ? ' ' . implode(' ', $attributes) : '';
    }

    /**
     * Render settings sidebar.
     *
     * @since    1.0.0
     * @access   private
     */
    private function render_settings_sidebar() {
        ?>
        <div class="wp-breach-settings-sidebar-content">
            <div class="sidebar-section">
                <h3><?php _e('Import/Export Settings', 'wp-breach'); ?></h3>
                <p><?php _e('Backup and restore your settings configuration.', 'wp-breach'); ?></p>
                
                <div class="sidebar-actions">
                    <button type="button" class="button button-secondary wp-breach-export-settings">
                        <span class="dashicons dashicons-download"></span>
                        <?php _e('Export Settings', 'wp-breach'); ?>
                    </button>
                    
                    <div class="import-section">
                        <input type="file" id="settings-import-file" accept=".json" style="display:none;">
                        <button type="button" class="button button-secondary wp-breach-import-settings">
                            <span class="dashicons dashicons-upload"></span>
                            <?php _e('Import Settings', 'wp-breach'); ?>
                        </button>
                    </div>
                </div>
            </div>

            <div class="sidebar-section">
                <h3><?php _e('Reset Settings', 'wp-breach'); ?></h3>
                <p><?php _e('Reset all settings to their default values.', 'wp-breach'); ?></p>
                
                <button type="button" class="button button-secondary wp-breach-reset-all">
                    <span class="dashicons dashicons-backup"></span>
                    <?php _e('Reset All Settings', 'wp-breach'); ?>
                </button>
            </div>

            <div class="sidebar-section">
                <h3><?php _e('Configuration Profiles', 'wp-breach'); ?></h3>
                <p><?php _e('Quick setup for common configurations.', 'wp-breach'); ?></p>
                
                <div class="profile-buttons">
                    <button type="button" class="button button-secondary wp-breach-apply-profile" data-profile="basic">
                        <?php _e('Basic Security', 'wp-breach'); ?>
                    </button>
                    <button type="button" class="button button-secondary wp-breach-apply-profile" data-profile="advanced">
                        <?php _e('Advanced Security', 'wp-breach'); ?>
                    </button>
                    <button type="button" class="button button-secondary wp-breach-apply-profile" data-profile="development">
                        <?php _e('Development Mode', 'wp-breach'); ?>
                    </button>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Render admin notices.
     *
     * @since    1.0.0
     * @access   private
     */
    private function render_notices() {
        foreach ($this->notices as $notice) {
            echo '<div class="notice notice-' . esc_attr($notice['type']) . (isset($notice['dismissible']) && $notice['dismissible'] ? ' is-dismissible' : '') . '">';
            echo '<p>' . wp_kses_post($notice['message']) . '</p>';
            echo '</div>';
        }
    }

    /**
     * Handle form submission.
     *
     * @since    1.0.0
     * @access   private
     */
    private function handle_form_submission() {
        if (!isset($_POST['action']) || $_POST['action'] !== 'save_settings') {
            return;
        }
        
        if (!wp_verify_nonce($_POST['wp_breach_settings_nonce'], 'wp_breach_settings_save')) {
            $this->add_notice(__('Security check failed. Please try again.', 'wp-breach'), 'error');
            return;
        }
        
        if (!current_user_can('manage_options')) {
            $this->add_notice(__('You do not have permission to save settings.', 'wp-breach'), 'error');
            return;
        }
        
        $group_name = sanitize_text_field($_POST['settings_group']);
        $group_key = 'wp_breach_settings_' . $group_name;
        
        if (!isset($_POST[$group_key])) {
            $this->add_notice(__('No settings data received.', 'wp-breach'), 'error');
            return;
        }
        
        $settings_data = $_POST[$group_key];
        $validated_settings = $this->validator->validate_group_settings($group_name, $settings_data);
        
        if ($this->validator->has_errors()) {
            $errors = $this->validator->get_formatted_errors();
            foreach ($errors as $field => $message) {
                $this->add_notice(sprintf(__('Error in %s: %s', 'wp-breach'), $field, $message), 'error');
            }
            return;
        }
        
        // Save settings
        foreach ($validated_settings as $setting_name => $value) {
            $this->manager->update_setting($group_name, $setting_name, $value);
        }
        
        $this->add_notice(__('Settings saved successfully.', 'wp-breach'), 'success');
        
        // Redirect to prevent resubmission
        wp_redirect(add_query_arg('tab', $group_name, admin_url('admin.php?page=wp-breach-settings')));
        exit;
    }

    /**
     * Sanitize settings group data.
     *
     * @since    1.0.0
     * @param    array    $input    Input data.
     * @return   array              Sanitized data.
     */
    public function sanitize_settings_group($input) {
        // Get the group name from the current context
        $group_name = str_replace('wp_breach_settings_', '', current_filter());
        
        if (!$input || !is_array($input)) {
            return $this->schema->get_group_defaults($group_name);
        }
        
        return $this->validator->validate_group_settings($group_name, $input);
    }

    /**
     * Handle settings import via AJAX.
     *
     * @since    1.0.0
     */
    public function handle_settings_import() {
        check_ajax_referer('wp_breach_settings_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permission denied.', 'wp-breach'));
        }
        
        if (!isset($_FILES['settings_file'])) {
            wp_send_json_error(__('No file uploaded.', 'wp-breach'));
        }
        
        $file = $_FILES['settings_file'];
        $file_content = file_get_contents($file['tmp_name']);
        $settings_data = json_decode($file_content, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            wp_send_json_error(__('Invalid JSON format.', 'wp-breach'));
        }
        
        $result = $this->manager->import_settings($settings_data);
        
        if ($result) {
            wp_send_json_success(__('Settings imported successfully.', 'wp-breach'));
        } else {
            wp_send_json_error(__('Failed to import settings.', 'wp-breach'));
        }
    }

    /**
     * Handle settings export via AJAX.
     *
     * @since    1.0.0
     */
    public function handle_settings_export() {
        check_ajax_referer('wp_breach_settings_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permission denied.', 'wp-breach'));
        }
        
        $settings = $this->manager->export_settings();
        
        wp_send_json_success(array(
            'data' => $settings,
            'filename' => 'wp-breach-settings-' . date('Y-m-d-H-i-s') . '.json'
        ));
    }

    /**
     * Handle settings reset via AJAX.
     *
     * @since    1.0.0
     */
    public function handle_settings_reset() {
        check_ajax_referer('wp_breach_settings_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permission denied.', 'wp-breach'));
        }
        
        $group = isset($_POST['group']) ? sanitize_text_field($_POST['group']) : 'all';
        $result = $this->manager->reset_settings($group);
        
        if ($result) {
            wp_send_json_success(__('Settings reset successfully.', 'wp-breach'));
        } else {
            wp_send_json_error(__('Failed to reset settings.', 'wp-breach'));
        }
    }

    /**
     * Determine the active tab.
     *
     * @since    1.0.0
     * @access   private
     */
    private function determine_active_tab() {
        $groups = $this->schema->get_settings_groups();
        $sorted_groups = $this->sort_groups_by_priority($groups);
        $available_tabs = array_keys($sorted_groups);
        
        $tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : '';
        
        if (!$tab || !in_array($tab, $available_tabs, true)) {
            $this->active_tab = $available_tabs[0]; // First tab as default
        } else {
            $this->active_tab = $tab;
        }
    }

    /**
     * Sort groups by priority.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $groups    Settings groups.
     * @return   array               Sorted groups.
     */
    private function sort_groups_by_priority($groups) {
        uasort($groups, function($a, $b) {
            $priority_a = isset($a['priority']) ? $a['priority'] : 99;
            $priority_b = isset($b['priority']) ? $b['priority'] : 99;
            return $priority_a - $priority_b;
        });
        
        return $groups;
    }

    /**
     * Add admin notice.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $message      Notice message.
     * @param    string   $type         Notice type (success, error, warning, info).
     * @param    bool     $dismissible  Whether notice is dismissible.
     */
    private function add_notice($message, $type = 'info', $dismissible = true) {
        $this->notices[] = array(
            'message' => $message,
            'type' => $type,
            'dismissible' => $dismissible
        );
    }

    /**
     * Get current active tab.
     *
     * @since    1.0.0
     * @return   string    Active tab name.
     */
    public function get_active_tab() {
        return $this->active_tab;
    }
}
