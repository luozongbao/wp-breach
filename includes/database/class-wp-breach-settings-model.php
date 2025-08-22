<?php
/**
 * Settings model class for database operations.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/database
 */

/**
 * Settings model class for database operations.
 *
 * Handles all database operations related to plugin settings
 * including configuration management, validation, and history tracking.
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/database
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Settings_Model extends WP_Breach_Base_Model {

	/**
	 * Get the table suffix for this model.
	 *
	 * @since    1.0.0
	 * @return   string    The table suffix.
	 */
	protected function get_table_suffix() {
		return 'breach_settings';
	}

	/**
	 * Get the validation rules for this model.
	 *
	 * @since    1.0.0
	 * @return   array    The validation rules.
	 */
	protected function get_validation_rules() {
		return array(
			'setting_group' => array(
				'required'   => true,
				'type'       => 'string',
				'max_length' => 50,
			),
			'setting_key' => array(
				'required'   => true,
				'type'       => 'string',
				'max_length' => 100,
			),
			'setting_value' => array(
				'required' => true,
				'type'     => 'string',
			),
			'data_type' => array(
				'required'   => true,
				'type'       => 'string',
				'max_length' => 20,
			),
		);
	}

	/**
	 * Get a setting value.
	 *
	 * @since    1.0.0
	 * @param    string   $group       The setting group.
	 * @param    string   $key         The setting key.
	 * @param    mixed    $default     Default value if setting not found.
	 * @return   mixed    The setting value or default.
	 */
	public function get_setting( $group, $key, $default = null ) {
		$setting = $this->get_by_fields( array(
			'setting_group' => $group,
			'setting_key'   => $key,
		) );

		if ( ! $setting ) {
			return $default;
		}

		return $this->parse_setting_value( $setting->setting_value, $setting->data_type );
	}

	/**
	 * Set a setting value.
	 *
	 * @since    1.0.0
	 * @param    string   $group       The setting group.
	 * @param    string   $key         The setting key.
	 * @param    mixed    $value       The setting value.
	 * @param    string   $data_type   The data type.
	 * @param    string   $description Optional description.
	 * @return   bool     True on success, false on failure.
	 */
	public function set_setting( $group, $key, $value, $data_type = 'string', $description = '' ) {
		$existing = $this->get_by_fields( array(
			'setting_group' => $group,
			'setting_key'   => $key,
		) );

		$setting_data = array(
			'setting_group' => $group,
			'setting_key'   => $key,
			'setting_value' => $this->serialize_setting_value( $value, $data_type ),
			'data_type'     => $data_type,
			'description'   => $description,
			'updated_by'    => get_current_user_id(),
			'updated_at'    => current_time( 'mysql' ),
		);

		if ( $existing ) {
			// Store old value in history before updating
			$this->store_setting_history( $existing );
			return $this->update( $existing->id, $setting_data );
		} else {
			$setting_data['created_at'] = current_time( 'mysql' );
			return $this->create( $setting_data );
		}
	}

	/**
	 * Get all settings in a group.
	 *
	 * @since    1.0.0
	 * @param    string   $group    The setting group.
	 * @return   array    Array of settings as key-value pairs.
	 */
	public function get_settings_group( $group ) {
		$settings = $this->get_all( array(
			'where' => array( 'setting_group' => $group ),
		) );

		$result = array();
		foreach ( $settings as $setting ) {
			$result[ $setting->setting_key ] = $this->parse_setting_value( 
				$setting->setting_value, 
				$setting->data_type 
			);
		}

		return $result;
	}

	/**
	 * Update multiple settings in a group.
	 *
	 * @since    1.0.0
	 * @param    string   $group       The setting group.
	 * @param    array    $settings    Array of key-value pairs.
	 * @param    array    $data_types  Array of data types for each setting.
	 * @return   bool     True on success, false on failure.
	 */
	public function update_settings_group( $group, $settings, $data_types = array() ) {
		$success = true;

		foreach ( $settings as $key => $value ) {
			$data_type = $data_types[ $key ] ?? $this->detect_data_type( $value );
			
			if ( ! $this->set_setting( $group, $key, $value, $data_type ) ) {
				$success = false;
			}
		}

		return $success;
	}

	/**
	 * Delete a setting.
	 *
	 * @since    1.0.0
	 * @param    string   $group    The setting group.
	 * @param    string   $key      The setting key.
	 * @return   bool     True on success, false on failure.
	 */
	public function delete_setting( $group, $key ) {
		$setting = $this->get_by_fields( array(
			'setting_group' => $group,
			'setting_key'   => $key,
		) );

		if ( ! $setting ) {
			return false;
		}

		// Store in history before deleting
		$this->store_setting_history( $setting, 'deleted' );

		return $this->delete( $setting->id );
	}

	/**
	 * Delete all settings in a group.
	 *
	 * @since    1.0.0
	 * @param    string   $group    The setting group.
	 * @return   int      Number of settings deleted.
	 */
	public function delete_settings_group( $group ) {
		$settings = $this->get_all( array(
			'where' => array( 'setting_group' => $group ),
		) );

		$deleted_count = 0;
		foreach ( $settings as $setting ) {
			if ( $this->delete_setting( $group, $setting->setting_key ) ) {
				$deleted_count++;
			}
		}

		return $deleted_count;
	}

	/**
	 * Get all setting groups.
	 *
	 * @since    1.0.0
	 * @return   array    Array of group names.
	 */
	public function get_setting_groups() {
		$sql = "SELECT DISTINCT setting_group FROM {$this->table_name} ORDER BY setting_group";
		$results = $this->wpdb->get_col( $sql );

		return $results ?: array();
	}

	/**
	 * Get settings by data type.
	 *
	 * @since    1.0.0
	 * @param    string   $data_type    The data type.
	 * @return   array    Array of setting objects.
	 */
	public function get_settings_by_type( $data_type ) {
		return $this->get_all( array(
			'where' => array( 'data_type' => $data_type ),
		) );
	}

	/**
	 * Get recently updated settings.
	 *
	 * @since    1.0.0
	 * @param    int    $limit    Number of settings to retrieve.
	 * @return   array  Array of recently updated settings.
	 */
	public function get_recently_updated( $limit = 10 ) {
		return $this->get_all( array(
			'limit'    => $limit,
			'order_by' => 'updated_at',
			'order'    => 'DESC',
		) );
	}

	/**
	 * Search settings by key or description.
	 *
	 * @since    1.0.0
	 * @param    string   $search_term    The search term.
	 * @param    string   $group          Optional group filter.
	 * @return   array    Array of matching settings.
	 */
	public function search_settings( $search_term, $group = null ) {
		$where_clause = "WHERE (setting_key LIKE %s OR description LIKE %s)";
		$params = array( "%{$search_term}%", "%{$search_term}%" );

		if ( $group ) {
			$where_clause .= " AND setting_group = %s";
			$params[] = $group;
		}

		$sql = "SELECT * FROM {$this->table_name} {$where_clause} ORDER BY setting_group, setting_key";

		return $this->wpdb->get_results( $this->wpdb->prepare( $sql, $params ) );
	}

	/**
	 * Get default settings for the plugin.
	 *
	 * @since    1.0.0
	 * @return   array    Array of default settings by group.
	 */
	public function get_default_settings() {
		return array(
			'general' => array(
				'enable_real_time_monitoring' => array(
					'value'       => true,
					'type'        => 'boolean',
					'description' => 'Enable real-time security monitoring',
				),
				'enable_auto_fixes' => array(
					'value'       => false,
					'type'        => 'boolean',
					'description' => 'Enable automatic vulnerability fixes',
				),
				'scan_frequency' => array(
					'value'       => 'daily',
					'type'        => 'string',
					'description' => 'Automatic scan frequency',
				),
				'notification_email' => array(
					'value'       => get_option( 'admin_email' ),
					'type'        => 'string',
					'description' => 'Email for security notifications',
				),
			),
			'scanning' => array(
				'scan_core_files' => array(
					'value'       => true,
					'type'        => 'boolean',
					'description' => 'Scan WordPress core files',
				),
				'scan_themes' => array(
					'value'       => true,
					'type'        => 'boolean',
					'description' => 'Scan theme files',
				),
				'scan_plugins' => array(
					'value'       => true,
					'type'        => 'boolean',
					'description' => 'Scan plugin files',
				),
				'scan_uploads' => array(
					'value'       => false,
					'type'        => 'boolean',
					'description' => 'Scan uploaded files',
				),
				'max_scan_duration' => array(
					'value'       => 3600,
					'type'        => 'integer',
					'description' => 'Maximum scan duration in seconds',
				),
			),
			'alerts' => array(
				'alert_critical' => array(
					'value'       => true,
					'type'        => 'boolean',
					'description' => 'Send alerts for critical vulnerabilities',
				),
				'alert_high' => array(
					'value'       => true,
					'type'        => 'boolean',
					'description' => 'Send alerts for high severity vulnerabilities',
				),
				'alert_medium' => array(
					'value'       => false,
					'type'        => 'boolean',
					'description' => 'Send alerts for medium severity vulnerabilities',
				),
				'alert_low' => array(
					'value'       => false,
					'type'        => 'boolean',
					'description' => 'Send alerts for low severity vulnerabilities',
				),
			),
			'performance' => array(
				'enable_caching' => array(
					'value'       => true,
					'type'        => 'boolean',
					'description' => 'Enable result caching',
				),
				'cache_duration' => array(
					'value'       => 3600,
					'type'        => 'integer',
					'description' => 'Cache duration in seconds',
				),
				'max_memory_usage' => array(
					'value'       => 128,
					'type'        => 'integer',
					'description' => 'Maximum memory usage in MB',
				),
			),
		);
	}

	/**
	 * Initialize default settings.
	 *
	 * @since    1.0.0
	 * @return   bool    True on success, false on failure.
	 */
	public function initialize_default_settings() {
		$defaults = $this->get_default_settings();
		$success = true;

		foreach ( $defaults as $group => $settings ) {
			foreach ( $settings as $key => $config ) {
				// Only set if doesn't exist
				$existing = $this->get_setting( $group, $key );
				if ( $existing === null ) {
					if ( ! $this->set_setting( 
						$group, 
						$key, 
						$config['value'], 
						$config['type'], 
						$config['description'] 
					) ) {
						$success = false;
					}
				}
			}
		}

		return $success;
	}

	/**
	 * Export settings.
	 *
	 * @since    1.0.0
	 * @param    array    $groups    Optional array of groups to export.
	 * @return   array    Exported settings data.
	 */
	public function export_settings( $groups = null ) {
		$where_clause = '';
		$params = array();

		if ( $groups ) {
			$placeholders = implode( ',', array_fill( 0, count( $groups ), '%s' ) );
			$where_clause = "WHERE setting_group IN ({$placeholders})";
			$params = $groups;
		}

		$sql = "SELECT * FROM {$this->table_name} {$where_clause} ORDER BY setting_group, setting_key";

		if ( $params ) {
			$settings = $this->wpdb->get_results( $this->wpdb->prepare( $sql, $params ) );
		} else {
			$settings = $this->wpdb->get_results( $sql );
		}

		$export_data = array(
			'export_date' => current_time( 'mysql' ),
			'plugin_version' => WP_BREACH_VERSION,
			'settings' => array(),
		);

		foreach ( $settings as $setting ) {
			if ( ! isset( $export_data['settings'][ $setting->setting_group ] ) ) {
				$export_data['settings'][ $setting->setting_group ] = array();
			}

			$export_data['settings'][ $setting->setting_group ][ $setting->setting_key ] = array(
				'value'       => $this->parse_setting_value( $setting->setting_value, $setting->data_type ),
				'type'        => $setting->data_type,
				'description' => $setting->description,
			);
		}

		return $export_data;
	}

	/**
	 * Import settings.
	 *
	 * @since    1.0.0
	 * @param    array    $import_data    The import data.
	 * @param    bool     $overwrite      Whether to overwrite existing settings.
	 * @return   array    Import results.
	 */
	public function import_settings( $import_data, $overwrite = false ) {
		$results = array(
			'imported' => 0,
			'skipped'  => 0,
			'errors'   => array(),
		);

		if ( ! isset( $import_data['settings'] ) || ! is_array( $import_data['settings'] ) ) {
			$results['errors'][] = 'Invalid import data format';
			return $results;
		}

		foreach ( $import_data['settings'] as $group => $settings ) {
			foreach ( $settings as $key => $config ) {
				$existing = $this->get_setting( $group, $key );

				if ( $existing !== null && ! $overwrite ) {
					$results['skipped']++;
					continue;
				}

				if ( $this->set_setting( 
					$group, 
					$key, 
					$config['value'], 
					$config['type'], 
					$config['description'] ?? '' 
				) ) {
					$results['imported']++;
				} else {
					$results['errors'][] = "Failed to import setting: {$group}.{$key}";
				}
			}
		}

		return $results;
	}

	/**
	 * Parse setting value based on data type.
	 *
	 * @since    1.0.0
	 * @param    string   $value       The stored value.
	 * @param    string   $data_type   The data type.
	 * @return   mixed    The parsed value.
	 */
	private function parse_setting_value( $value, $data_type ) {
		switch ( $data_type ) {
			case 'boolean':
				return (bool) $value;
			case 'integer':
				return (int) $value;
			case 'float':
				return (float) $value;
			case 'array':
			case 'object':
				return json_decode( $value, true );
			case 'string':
			default:
				return $value;
		}
	}

	/**
	 * Serialize setting value for storage.
	 *
	 * @since    1.0.0
	 * @param    mixed    $value       The value to serialize.
	 * @param    string   $data_type   The data type.
	 * @return   string   The serialized value.
	 */
	private function serialize_setting_value( $value, $data_type ) {
		switch ( $data_type ) {
			case 'boolean':
				return $value ? '1' : '0';
			case 'array':
			case 'object':
				return wp_json_encode( $value );
			default:
				return (string) $value;
		}
	}

	/**
	 * Detect data type of a value.
	 *
	 * @since    1.0.0
	 * @param    mixed    $value    The value.
	 * @return   string   The detected data type.
	 */
	private function detect_data_type( $value ) {
		if ( is_bool( $value ) ) {
			return 'boolean';
		} elseif ( is_int( $value ) ) {
			return 'integer';
		} elseif ( is_float( $value ) ) {
			return 'float';
		} elseif ( is_array( $value ) ) {
			return 'array';
		} elseif ( is_object( $value ) ) {
			return 'object';
		} else {
			return 'string';
		}
	}

	/**
	 * Store setting history.
	 *
	 * @since    1.0.0
	 * @param    object   $setting    The setting object.
	 * @param    string   $action     The action performed.
	 * @return   void
	 */
	private function store_setting_history( $setting, $action = 'updated' ) {
		// This would ideally use a separate history table
		// For now, we'll log to WordPress debug log if WP_DEBUG is enabled
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( sprintf(
				'WP-Breach Setting %s: %s.%s = %s (by user %d)',
				$action,
				$setting->setting_group,
				$setting->setting_key,
				$setting->setting_value,
				get_current_user_id()
			) );
		}
	}

	/**
	 * Validate setting value.
	 *
	 * @since    1.0.0
	 * @param    string   $group       The setting group.
	 * @param    string   $key         The setting key.
	 * @param    mixed    $value       The value to validate.
	 * @param    string   $data_type   The expected data type.
	 * @return   bool     True if valid, false otherwise.
	 */
	public function validate_setting( $group, $key, $value, $data_type ) {
		// Basic type validation
		switch ( $data_type ) {
			case 'boolean':
				return is_bool( $value ) || in_array( $value, array( 0, 1, '0', '1', 'true', 'false' ), true );
			case 'integer':
				return is_numeric( $value ) && intval( $value ) == $value;
			case 'float':
				return is_numeric( $value );
			case 'array':
				return is_array( $value );
			case 'object':
				return is_object( $value ) || is_array( $value );
			case 'string':
				return is_string( $value ) || is_scalar( $value );
		}

		// Custom validation rules can be added here based on group/key
		return true;
	}

	/**
	 * Get all settings organized by group.
	 *
	 * @since    1.0.0
	 * @return   array    Settings organized by group.
	 */
	public function get_all_settings() {
		$all_settings = $this->get_all();
		$organized_settings = array();

		foreach ( $all_settings as $setting ) {
			$group = $setting->setting_group;
			$key = $setting->setting_key;
			
			if ( ! isset( $organized_settings[ $group ] ) ) {
				$organized_settings[ $group ] = array();
			}
			
			// Decode JSON values
			$value = $setting->setting_value;
			if ( $this->is_json( $value ) ) {
				$value = json_decode( $value, true );
			}
			
			$organized_settings[ $group ][ $key ] = $value;
		}

		return $organized_settings;
	}

	/**
	 * Check if a string is valid JSON.
	 *
	 * @since    1.0.0
	 * @param    string   $string   String to check.
	 * @return   bool     True if valid JSON.
	 */
	private function is_json( $string ) {
		if ( ! is_string( $string ) ) {
			return false;
		}
		
		json_decode( $string );
		return ( json_last_error() == JSON_ERROR_NONE );
	}
}
