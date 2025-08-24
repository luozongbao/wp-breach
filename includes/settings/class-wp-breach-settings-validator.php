<?php

/**
 * Settings Validator for WP-Breach.
 *
 * This class handles validation and sanitization of all plugin settings
 * using the schema definitions and custom validation rules.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/settings
 */

/**
 * The settings validator class.
 *
 * Provides comprehensive validation and sanitization for all settings
 * with support for custom validation rules and error reporting.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/settings
 * @author     WP Breach Team
 */
class WP_Breach_Settings_Validator {

    /**
     * Settings schema instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Breach_Settings_Schema    $schema    Schema instance.
     */
    private $schema;

    /**
     * Validation errors.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $errors    Validation errors.
     */
    private $errors;

    /**
     * Initialize the validator.
     *
     * @since    1.0.0
     * @param    WP_Breach_Settings_Schema    $schema    Schema instance.
     */
    public function __construct($schema) {
        $this->schema = $schema;
        $this->errors = array();
    }

    /**
     * Validate and sanitize a single setting value.
     *
     * @since    1.0.0
     * @param    string   $group_name      Group name.
     * @param    string   $setting_name    Setting name.
     * @param    mixed    $value           Setting value.
     * @param    array    $context         Additional context for validation.
     * @return   mixed                     Validated and sanitized value.
     */
    public function validate_setting($group_name, $setting_name, $value, $context = array()) {
        $this->clear_errors();
        
        $config = $this->schema->get_setting_config($group_name, $setting_name);
        
        if (!$config) {
            $this->add_error($setting_name, sprintf(
                __('Setting %s not found in group %s', 'wp-breach'),
                $setting_name,
                $group_name
            ));
            return null;
        }

        // Check dependencies first
        if ($this->schema->setting_has_dependencies($group_name, $setting_name)) {
            $dependencies = $this->schema->get_setting_dependencies($group_name, $setting_name);
            if (!$this->check_dependencies($dependencies, $context)) {
                // If dependencies not met, return default value
                return $this->schema->get_setting_default($group_name, $setting_name);
            }
        }

        // Apply type-based validation
        $value = $this->validate_by_type($config['type'], $value, $config, $setting_name);
        
        // Apply validation rules
        if (isset($config['validation']) && !empty($this->errors)) {
            $value = $this->apply_validation_rules($value, $config['validation'], $setting_name);
        }

        // Apply custom validation
        if (isset($config['validation']['custom'])) {
            $value = $this->apply_custom_validation($value, $config['validation']['custom'], $setting_name, $context);
        }

        return $value;
    }

    /**
     * Validate and sanitize multiple settings.
     *
     * @since    1.0.0
     * @param    string   $group_name    Group name.
     * @param    array    $values        Settings values.
     * @return   array                   Validated and sanitized values.
     */
    public function validate_group_settings($group_name, $values) {
        $this->clear_errors();
        $validated = array();
        $context = $values; // Provide full context for dependency checking
        
        foreach ($values as $setting_name => $value) {
            $validated[$setting_name] = $this->validate_setting(
                $group_name,
                $setting_name,
                $value,
                $context
            );
        }

        return $validated;
    }

    /**
     * Validate by setting type.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $type           Setting type.
     * @param    mixed    $value          Setting value.
     * @param    array    $config         Setting configuration.
     * @param    string   $setting_name   Setting name for error reporting.
     * @return   mixed                    Validated value.
     */
    private function validate_by_type($type, $value, $config, $setting_name) {
        switch ($type) {
            case 'text':
            case 'textarea':
                return $this->validate_string($value, $config, $setting_name);
                
            case 'email':
                return $this->validate_email($value, $setting_name);
                
            case 'url':
                return $this->validate_url($value, $setting_name);
                
            case 'number':
            case 'range':
                return $this->validate_number($value, $config, $setting_name);
                
            case 'checkbox':
                return $this->validate_boolean($value);
                
            case 'select':
                return $this->validate_select($value, $config, $setting_name);
                
            case 'multiselect':
                return $this->validate_multiselect($value, $config, $setting_name);
                
            case 'time':
                return $this->validate_time($value, $setting_name);
                
            case 'date':
                return $this->validate_date($value, $setting_name);
                
            case 'color':
                return $this->validate_color($value, $setting_name);
                
            default:
                return sanitize_text_field($value);
        }
    }

    /**
     * Validate string value.
     *
     * @since    1.0.0
     * @access   private
     * @param    mixed    $value          Value to validate.
     * @param    array    $config         Setting configuration.
     * @param    string   $setting_name   Setting name.
     * @return   string                   Validated string.
     */
    private function validate_string($value, $config, $setting_name) {
        if (!is_string($value)) {
            $value = (string) $value;
        }

        // Sanitize the string
        if ($config['type'] === 'textarea') {
            $value = sanitize_textarea_field($value);
        } else {
            $value = sanitize_text_field($value);
        }

        // Check length constraints
        if (isset($config['minlength']) && strlen($value) < $config['minlength']) {
            $this->add_error($setting_name, sprintf(
                __('Value must be at least %d characters long', 'wp-breach'),
                $config['minlength']
            ));
        }

        if (isset($config['maxlength']) && strlen($value) > $config['maxlength']) {
            $this->add_error($setting_name, sprintf(
                __('Value must be no more than %d characters long', 'wp-breach'),
                $config['maxlength']
            ));
            $value = substr($value, 0, $config['maxlength']);
        }

        return $value;
    }

    /**
     * Validate email value.
     *
     * @since    1.0.0
     * @access   private
     * @param    mixed    $value          Value to validate.
     * @param    string   $setting_name   Setting name.
     * @return   string                   Validated email.
     */
    private function validate_email($value, $setting_name) {
        $value = sanitize_email($value);
        
        if (!is_email($value)) {
            $this->add_error($setting_name, __('Invalid email address', 'wp-breach'));
        }

        return $value;
    }

    /**
     * Validate URL value.
     *
     * @since    1.0.0
     * @access   private
     * @param    mixed    $value          Value to validate.
     * @param    string   $setting_name   Setting name.
     * @return   string                   Validated URL.
     */
    private function validate_url($value, $setting_name) {
        $value = esc_url_raw($value);
        
        if (!filter_var($value, FILTER_VALIDATE_URL)) {
            $this->add_error($setting_name, __('Invalid URL format', 'wp-breach'));
        }

        return $value;
    }

    /**
     * Validate number value.
     *
     * @since    1.0.0
     * @access   private
     * @param    mixed    $value          Value to validate.
     * @param    array    $config         Setting configuration.
     * @param    string   $setting_name   Setting name.
     * @return   int|float                Validated number.
     */
    private function validate_number($value, $config, $setting_name) {
        if (!is_numeric($value)) {
            $this->add_error($setting_name, __('Value must be a number', 'wp-breach'));
            return isset($config['default']) ? $config['default'] : 0;
        }

        // Convert to appropriate type
        if (isset($config['step']) && $config['step'] < 1) {
            $value = (float) $value;
        } else {
            $value = (int) $value;
        }

        // Check min/max constraints
        if (isset($config['min']) && $value < $config['min']) {
            $this->add_error($setting_name, sprintf(
                __('Value must be at least %s', 'wp-breach'),
                $config['min']
            ));
            $value = $config['min'];
        }

        if (isset($config['max']) && $value > $config['max']) {
            $this->add_error($setting_name, sprintf(
                __('Value must be no more than %s', 'wp-breach'),
                $config['max']
            ));
            $value = $config['max'];
        }

        return $value;
    }

    /**
     * Validate boolean value.
     *
     * @since    1.0.0
     * @access   private
     * @param    mixed    $value    Value to validate.
     * @return   bool               Validated boolean.
     */
    private function validate_boolean($value) {
        if (is_string($value)) {
            $value = strtolower($value);
            return in_array($value, array('1', 'true', 'yes', 'on'), true);
        }
        
        return (bool) $value;
    }

    /**
     * Validate select value.
     *
     * @since    1.0.0
     * @access   private
     * @param    mixed    $value          Value to validate.
     * @param    array    $config         Setting configuration.
     * @param    string   $setting_name   Setting name.
     * @return   string                   Validated select value.
     */
    private function validate_select($value, $config, $setting_name) {
        $value = sanitize_text_field($value);
        
        if (isset($config['options']) && !array_key_exists($value, $config['options'])) {
            $this->add_error($setting_name, __('Invalid selection', 'wp-breach'));
            return isset($config['default']) ? $config['default'] : '';
        }

        return $value;
    }

    /**
     * Validate multiselect value.
     *
     * @since    1.0.0
     * @access   private
     * @param    mixed    $value          Value to validate.
     * @param    array    $config         Setting configuration.
     * @param    string   $setting_name   Setting name.
     * @return   array                    Validated multiselect value.
     */
    private function validate_multiselect($value, $config, $setting_name) {
        if (!is_array($value)) {
            $this->add_error($setting_name, __('Value must be an array', 'wp-breach'));
            return isset($config['default']) ? $config['default'] : array();
        }

        $valid_values = array();
        
        if (isset($config['options'])) {
            foreach ($value as $item) {
                $item = sanitize_text_field($item);
                if (array_key_exists($item, $config['options'])) {
                    $valid_values[] = $item;
                } else {
                    $this->add_error($setting_name, sprintf(
                        __('Invalid selection: %s', 'wp-breach'),
                        $item
                    ));
                }
            }
        } else {
            $valid_values = array_map('sanitize_text_field', $value);
        }

        return $valid_values;
    }

    /**
     * Validate time value.
     *
     * @since    1.0.0
     * @access   private
     * @param    mixed    $value          Value to validate.
     * @param    string   $setting_name   Setting name.
     * @return   string                   Validated time.
     */
    private function validate_time($value, $setting_name) {
        $value = sanitize_text_field($value);
        
        if (!preg_match('/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/', $value)) {
            $this->add_error($setting_name, __('Invalid time format. Use HH:MM format.', 'wp-breach'));
        }

        return $value;
    }

    /**
     * Validate date value.
     *
     * @since    1.0.0
     * @access   private
     * @param    mixed    $value          Value to validate.
     * @param    string   $setting_name   Setting name.
     * @return   string                   Validated date.
     */
    private function validate_date($value, $setting_name) {
        $value = sanitize_text_field($value);
        
        if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)) {
            $this->add_error($setting_name, __('Invalid date format. Use YYYY-MM-DD format.', 'wp-breach'));
        } else {
            $date = DateTime::createFromFormat('Y-m-d', $value);
            if (!$date || $date->format('Y-m-d') !== $value) {
                $this->add_error($setting_name, __('Invalid date value', 'wp-breach'));
            }
        }

        return $value;
    }

    /**
     * Validate color value.
     *
     * @since    1.0.0
     * @access   private
     * @param    mixed    $value          Value to validate.
     * @param    string   $setting_name   Setting name.
     * @return   string                   Validated color.
     */
    private function validate_color($value, $setting_name) {
        $value = sanitize_hex_color($value);
        
        if (empty($value)) {
            $this->add_error($setting_name, __('Invalid color format. Use hex color codes.', 'wp-breach'));
        }

        return $value;
    }

    /**
     * Apply validation rules.
     *
     * @since    1.0.0
     * @access   private
     * @param    mixed    $value          Value to validate.
     * @param    array    $rules          Validation rules.
     * @param    string   $setting_name   Setting name.
     * @return   mixed                    Validated value.
     */
    private function apply_validation_rules($value, $rules, $setting_name) {
        // Required validation
        if (isset($rules['required']) && $rules['required'] && empty($value)) {
            $this->add_error($setting_name, __('This field is required', 'wp-breach'));
        }

        // Pattern validation
        if (isset($rules['pattern']) && !empty($value)) {
            if (!preg_match($rules['pattern'], $value)) {
                $this->add_error($setting_name, __('Value does not match required pattern', 'wp-breach'));
            }
        }

        // Enum validation
        if (isset($rules['enum']) && !empty($value)) {
            if (!in_array($value, $rules['enum'], true)) {
                $this->add_error($setting_name, __('Value must be one of the allowed options', 'wp-breach'));
            }
        }

        // Type-specific validation
        if (isset($rules['type'])) {
            switch ($rules['type']) {
                case 'integer':
                    if (!is_int($value) && !ctype_digit($value)) {
                        $this->add_error($setting_name, __('Value must be an integer', 'wp-breach'));
                    }
                    break;
                    
                case 'float':
                    if (!is_float($value) && !is_numeric($value)) {
                        $this->add_error($setting_name, __('Value must be a number', 'wp-breach'));
                    }
                    break;
                    
                case 'string':
                    if (!is_string($value)) {
                        $this->add_error($setting_name, __('Value must be a string', 'wp-breach'));
                    }
                    break;
                    
                case 'array':
                    if (!is_array($value)) {
                        $this->add_error($setting_name, __('Value must be an array', 'wp-breach'));
                    }
                    break;
                    
                case 'boolean':
                    // Boolean validation handled in validate_boolean
                    break;
            }
        }

        return $value;
    }

    /**
     * Apply custom validation.
     *
     * @since    1.0.0
     * @access   private
     * @param    mixed    $value             Value to validate.
     * @param    string   $validation_func   Custom validation function name.
     * @param    string   $setting_name      Setting name.
     * @param    array    $context           Validation context.
     * @return   mixed                       Validated value.
     */
    private function apply_custom_validation($value, $validation_func, $setting_name, $context = array()) {
        if (method_exists($this, $validation_func)) {
            return $this->$validation_func($value, $setting_name, $context);
        }
        
        // Allow external custom validators
        $validated_value = apply_filters(
            'wp_breach_custom_validation_' . $validation_func,
            $value,
            $setting_name,
            $context,
            $this
        );
        
        return $validated_value !== null ? $validated_value : $value;
    }

    /**
     * Custom validation for email list.
     *
     * @since    1.0.0
     * @param    string   $value          Email list value.
     * @param    string   $setting_name   Setting name.
     * @param    array    $context        Validation context.
     * @return   string                   Validated email list.
     */
    public function validate_email_list($value, $setting_name, $context = array()) {
        $emails = array_filter(array_map('trim', explode("\n", $value)));
        $valid_emails = array();
        
        foreach ($emails as $email) {
            if (is_email($email)) {
                $valid_emails[] = $email;
            } else {
                $this->add_error($setting_name, sprintf(
                    __('Invalid email address: %s', 'wp-breach'),
                    $email
                ));
            }
        }
        
        return implode("\n", $valid_emails);
    }

    /**
     * Check setting dependencies.
     *
     * @since    1.0.0
     * @access   private
     * @param    array    $dependencies    Dependencies configuration.
     * @param    array    $context         Current values context.
     * @return   bool                      Dependencies are met.
     */
    private function check_dependencies($dependencies, $context) {
        if (!isset($dependencies['field']) || !isset($dependencies['value'])) {
            return true;
        }
        
        $field_value = isset($context[$dependencies['field']]) 
            ? $context[$dependencies['field']] 
            : null;
            
        return $field_value === $dependencies['value'];
    }

    /**
     * Add validation error.
     *
     * @since    1.0.0
     * @access   private
     * @param    string   $field      Field name.
     * @param    string   $message    Error message.
     */
    private function add_error($field, $message) {
        if (!isset($this->errors[$field])) {
            $this->errors[$field] = array();
        }
        
        $this->errors[$field][] = $message;
    }

    /**
     * Get validation errors.
     *
     * @since    1.0.0
     * @return   array    Validation errors.
     */
    public function get_errors() {
        return $this->errors;
    }

    /**
     * Check if there are validation errors.
     *
     * @since    1.0.0
     * @return   bool    Has errors.
     */
    public function has_errors() {
        return !empty($this->errors);
    }

    /**
     * Get errors for a specific field.
     *
     * @since    1.0.0
     * @param    string   $field    Field name.
     * @return   array              Field errors.
     */
    public function get_field_errors($field) {
        return isset($this->errors[$field]) ? $this->errors[$field] : array();
    }

    /**
     * Clear validation errors.
     *
     * @since    1.0.0
     */
    public function clear_errors() {
        $this->errors = array();
    }

    /**
     * Get formatted error messages.
     *
     * @since    1.0.0
     * @return   array    Formatted error messages.
     */
    public function get_formatted_errors() {
        $formatted = array();
        
        foreach ($this->errors as $field => $messages) {
            $formatted[$field] = implode(', ', $messages);
        }
        
        return $formatted;
    }

    /**
     * Validate all settings against schema.
     *
     * @since    1.0.0
     * @param    array    $settings    All settings to validate.
     * @return   array                 Validated settings.
     */
    public function validate_all_settings($settings) {
        $this->clear_errors();
        $validated = array();
        
        foreach ($settings as $group_name => $group_settings) {
            if (is_array($group_settings)) {
                $validated[$group_name] = $this->validate_group_settings($group_name, $group_settings);
            }
        }
        
        return $validated;
    }

    /**
     * Sanitize settings for export.
     *
     * @since    1.0.0
     * @param    array    $settings    Settings to sanitize.
     * @return   array                 Sanitized settings.
     */
    public function sanitize_for_export($settings) {
        $sanitized = array();
        
        foreach ($settings as $group_name => $group_settings) {
            if (!is_array($group_settings)) {
                continue;
            }
            
            $sanitized[$group_name] = array();
            $sensitive_settings = $this->schema->get_sensitive_settings($group_name);
            
            foreach ($group_settings as $setting_name => $value) {
                if (in_array($setting_name, $sensitive_settings, true)) {
                    // Exclude sensitive settings from export
                    continue;
                }
                
                $sanitized[$group_name][$setting_name] = $value;
            }
        }
        
        return $sanitized;
    }
}
