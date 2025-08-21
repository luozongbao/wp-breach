<?php
/**
 * Base model class for database operations.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/database
 */

/**
 * Base model class for database operations.
 *
 * Provides common functionality for all model classes including CRUD operations,
 * data validation, and query building.
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/database
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
abstract class WP_Breach_Base_Model {

	/**
	 * The WordPress database object.
	 *
	 * @since    1.0.0
	 * @access   protected
	 * @var      wpdb    $wpdb    The WordPress database object.
	 */
	protected $wpdb;

	/**
	 * The table name.
	 *
	 * @since    1.0.0
	 * @access   protected
	 * @var      string    $table_name    The table name.
	 */
	protected $table_name;

	/**
	 * The primary key column.
	 *
	 * @since    1.0.0
	 * @access   protected
	 * @var      string    $primary_key    The primary key column.
	 */
	protected $primary_key = 'id';

	/**
	 * Initialize the model.
	 *
	 * @since    1.0.0
	 */
	public function __construct() {
		global $wpdb;
		$this->wpdb = $wpdb;
		$this->table_name = $this->wpdb->prefix . $this->get_table_suffix();
	}

	/**
	 * Get the table suffix for this model.
	 *
	 * @since    1.0.0
	 * @return   string    The table suffix.
	 */
	abstract protected function get_table_suffix();

	/**
	 * Get the validation rules for this model.
	 *
	 * @since    1.0.0
	 * @return   array    The validation rules.
	 */
	abstract protected function get_validation_rules();

	/**
	 * Create a new record.
	 *
	 * @since    1.0.0
	 * @param    array    $data    The data to insert.
	 * @return   int|false    The inserted record ID or false on failure.
	 */
	public function create( $data ) {
		$data = $this->sanitize_data( $data );
		
		if ( ! $this->validate_data( $data ) ) {
			return false;
		}

		$data = $this->prepare_for_insert( $data );
		
		$result = $this->wpdb->insert(
			$this->table_name,
			$data,
			$this->get_format_array( $data )
		);

		if ( false === $result ) {
			error_log( 'WP-Breach: Database insert failed: ' . $this->wpdb->last_error );
			return false;
		}

		return $this->wpdb->insert_id;
	}

	/**
	 * Update a record.
	 *
	 * @since    1.0.0
	 * @param    int      $id      The record ID.
	 * @param    array    $data    The data to update.
	 * @return   bool     True on success, false on failure.
	 */
	public function update( $id, $data ) {
		$data = $this->sanitize_data( $data );
		
		if ( ! $this->validate_data( $data, $id ) ) {
			return false;
		}

		$data = $this->prepare_for_update( $data );
		
		$result = $this->wpdb->update(
			$this->table_name,
			$data,
			array( $this->primary_key => $id ),
			$this->get_format_array( $data ),
			array( '%d' )
		);

		if ( false === $result ) {
			error_log( 'WP-Breach: Database update failed: ' . $this->wpdb->last_error );
			return false;
		}

		return true;
	}

	/**
	 * Delete a record.
	 *
	 * @since    1.0.0
	 * @param    int    $id    The record ID.
	 * @return   bool   True on success, false on failure.
	 */
	public function delete( $id ) {
		$result = $this->wpdb->delete(
			$this->table_name,
			array( $this->primary_key => $id ),
			array( '%d' )
		);

		if ( false === $result ) {
			error_log( 'WP-Breach: Database delete failed: ' . $this->wpdb->last_error );
			return false;
		}

		return $result > 0;
	}

	/**
	 * Get a record by ID.
	 *
	 * @since    1.0.0
	 * @param    int    $id    The record ID.
	 * @return   object|null    The record object or null if not found.
	 */
	public function get( $id ) {
		$result = $this->wpdb->get_row( $this->wpdb->prepare(
			"SELECT * FROM {$this->table_name} WHERE {$this->primary_key} = %d",
			$id
		) );

		return $result ? $this->format_output( $result ) : null;
	}

	/**
	 * Get multiple records.
	 *
	 * @since    1.0.0
	 * @param    array    $args    Query arguments.
	 * @return   array    Array of record objects.
	 */
	public function get_all( $args = array() ) {
		$defaults = array(
			'limit'     => 100,
			'offset'    => 0,
			'order_by'  => $this->primary_key,
			'order'     => 'DESC',
			'where'     => array(),
		);

		$args = wp_parse_args( $args, $defaults );

		$sql = "SELECT * FROM {$this->table_name}";

		// Add WHERE clause
		if ( ! empty( $args['where'] ) ) {
			$where_clauses = array();
			foreach ( $args['where'] as $column => $value ) {
				if ( is_array( $value ) ) {
					$placeholders = implode( ',', array_fill( 0, count( $value ), '%s' ) );
					$where_clauses[] = $this->wpdb->prepare( "{$column} IN ({$placeholders})", $value );
				} else {
					$where_clauses[] = $this->wpdb->prepare( "{$column} = %s", $value );
				}
			}
			$sql .= ' WHERE ' . implode( ' AND ', $where_clauses );
		}

		// Add ORDER BY clause
		$sql .= " ORDER BY {$args['order_by']} {$args['order']}";

		// Add LIMIT clause
		if ( $args['limit'] > 0 ) {
			$sql .= $this->wpdb->prepare( " LIMIT %d OFFSET %d", $args['limit'], $args['offset'] );
		}

		$results = $this->wpdb->get_results( $sql );

		if ( ! $results ) {
			return array();
		}

		return array_map( array( $this, 'format_output' ), $results );
	}

	/**
	 * Count records.
	 *
	 * @since    1.0.0
	 * @param    array    $where    WHERE conditions.
	 * @return   int      The record count.
	 */
	public function count( $where = array() ) {
		$sql = "SELECT COUNT(*) FROM {$this->table_name}";

		if ( ! empty( $where ) ) {
			$where_clauses = array();
			foreach ( $where as $column => $value ) {
				if ( is_array( $value ) ) {
					$placeholders = implode( ',', array_fill( 0, count( $value ), '%s' ) );
					$where_clauses[] = $this->wpdb->prepare( "{$column} IN ({$placeholders})", $value );
				} else {
					$where_clauses[] = $this->wpdb->prepare( "{$column} = %s", $value );
				}
			}
			$sql .= ' WHERE ' . implode( ' AND ', $where_clauses );
		}

		return intval( $this->wpdb->get_var( $sql ) );
	}

	/**
	 * Check if a record exists.
	 *
	 * @since    1.0.0
	 * @param    int    $id    The record ID.
	 * @return   bool   True if exists, false otherwise.
	 */
	public function exists( $id ) {
		$result = $this->wpdb->get_var( $this->wpdb->prepare(
			"SELECT COUNT(*) FROM {$this->table_name} WHERE {$this->primary_key} = %d",
			$id
		) );

		return intval( $result ) > 0;
	}

	/**
	 * Sanitize data before database operations.
	 *
	 * @since    1.0.0
	 * @param    array    $data    The data to sanitize.
	 * @return   array    The sanitized data.
	 */
	protected function sanitize_data( $data ) {
		$sanitized = array();

		foreach ( $data as $key => $value ) {
			if ( is_string( $value ) ) {
				$sanitized[ $key ] = sanitize_text_field( $value );
			} elseif ( is_array( $value ) || is_object( $value ) ) {
				$sanitized[ $key ] = wp_json_encode( $value );
			} else {
				$sanitized[ $key ] = $value;
			}
		}

		return $sanitized;
	}

	/**
	 * Validate data against model rules.
	 *
	 * @since    1.0.0
	 * @param    array    $data    The data to validate.
	 * @param    int      $id      The record ID (for updates).
	 * @return   bool     True if valid, false otherwise.
	 */
	protected function validate_data( $data, $id = null ) {
		$rules = $this->get_validation_rules();

		foreach ( $rules as $field => $rule ) {
			// Check required fields
			if ( isset( $rule['required'] ) && $rule['required'] && empty( $data[ $field ] ) ) {
				error_log( "WP-Breach: Validation failed - {$field} is required" );
				return false;
			}

			// Check field types
			if ( isset( $data[ $field ] ) && isset( $rule['type'] ) ) {
				if ( ! $this->validate_field_type( $data[ $field ], $rule['type'] ) ) {
					error_log( "WP-Breach: Validation failed - {$field} has invalid type" );
					return false;
				}
			}

			// Check maximum length
			if ( isset( $data[ $field ] ) && isset( $rule['max_length'] ) ) {
				if ( strlen( $data[ $field ] ) > $rule['max_length'] ) {
					error_log( "WP-Breach: Validation failed - {$field} exceeds maximum length" );
					return false;
				}
			}
		}

		return true;
	}

	/**
	 * Validate field type.
	 *
	 * @since    1.0.0
	 * @param    mixed    $value    The value to validate.
	 * @param    string   $type     The expected type.
	 * @return   bool     True if valid, false otherwise.
	 */
	private function validate_field_type( $value, $type ) {
		switch ( $type ) {
			case 'int':
			case 'integer':
				return is_numeric( $value );
			case 'string':
				return is_string( $value );
			case 'bool':
			case 'boolean':
				return is_bool( $value ) || in_array( $value, array( 0, 1, '0', '1' ), true );
			case 'email':
				return is_email( $value );
			case 'url':
				return filter_var( $value, FILTER_VALIDATE_URL ) !== false;
			case 'json':
				json_decode( $value );
				return json_last_error() === JSON_ERROR_NONE;
			default:
				return true;
		}
	}

	/**
	 * Prepare data for database insertion.
	 *
	 * @since    1.0.0
	 * @param    array    $data    The data to prepare.
	 * @return   array    The prepared data.
	 */
	protected function prepare_for_insert( $data ) {
		// Add created_at timestamp if not set
		if ( ! isset( $data['created_at'] ) ) {
			$data['created_at'] = current_time( 'mysql' );
		}

		// Add updated_at timestamp if not set
		if ( ! isset( $data['updated_at'] ) ) {
			$data['updated_at'] = current_time( 'mysql' );
		}

		return $data;
	}

	/**
	 * Prepare data for database update.
	 *
	 * @since    1.0.0
	 * @param    array    $data    The data to prepare.
	 * @return   array    The prepared data.
	 */
	protected function prepare_for_update( $data ) {
		// Update the updated_at timestamp
		$data['updated_at'] = current_time( 'mysql' );

		return $data;
	}

	/**
	 * Format output data.
	 *
	 * @since    1.0.0
	 * @param    object   $data    The raw database data.
	 * @return   object   The formatted data.
	 */
	protected function format_output( $data ) {
		// Convert JSON strings back to arrays/objects
		foreach ( $data as $key => $value ) {
			if ( $this->is_json_field( $key ) && is_string( $value ) && ! empty( $value ) ) {
				$decoded = json_decode( $value, true );
				if ( json_last_error() === JSON_ERROR_NONE ) {
					$data->$key = $decoded;
				}
			}
		}

		return $data;
	}

	/**
	 * Check if a field should be treated as JSON.
	 *
	 * @since    1.0.0
	 * @param    string   $field_name    The field name.
	 * @return   bool     True if JSON field, false otherwise.
	 */
	protected function is_json_field( $field_name ) {
		$json_fields = array(
			'configuration',
			'summary_data',
			'raw_data',
			'rollback_data',
			'fix_details',
			'before_snapshot',
			'after_snapshot',
			'event_data',
			'references',
			'affected_software',
		);

		return in_array( $field_name, $json_fields, true );
	}

	/**
	 * Get format array for wpdb operations.
	 *
	 * @since    1.0.0
	 * @param    array    $data    The data array.
	 * @return   array    The format array.
	 */
	protected function get_format_array( $data ) {
		$formats = array();

		foreach ( $data as $key => $value ) {
			if ( is_int( $value ) ) {
				$formats[] = '%d';
			} elseif ( is_float( $value ) ) {
				$formats[] = '%f';
			} else {
				$formats[] = '%s';
			}
		}

		return $formats;
	}

	/**
	 * Execute a custom query.
	 *
	 * @since    1.0.0
	 * @param    string   $sql    The SQL query.
	 * @param    array    $args   Query arguments.
	 * @return   mixed    Query results.
	 */
	protected function query( $sql, $args = array() ) {
		if ( ! empty( $args ) ) {
			$sql = $this->wpdb->prepare( $sql, $args );
		}

		return $this->wpdb->get_results( $sql );
	}

	/**
	 * Begin database transaction.
	 *
	 * @since    1.0.0
	 */
	protected function begin_transaction() {
		$this->wpdb->query( 'START TRANSACTION' );
	}

	/**
	 * Commit database transaction.
	 *
	 * @since    1.0.0
	 */
	protected function commit_transaction() {
		$this->wpdb->query( 'COMMIT' );
	}

	/**
	 * Rollback database transaction.
	 *
	 * @since    1.0.0
	 */
	protected function rollback_transaction() {
		$this->wpdb->query( 'ROLLBACK' );
	}
}
