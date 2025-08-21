<?php
/**
 * The public-facing functionality of the plugin.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/public
 */

/**
 * The public-facing functionality of the plugin.
 *
 * Defines the plugin name, version, and hooks for the public-facing side of the site.
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/public
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Public {

	/**
	 * The ID of this plugin.
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      string    $plugin_name    The ID of this plugin.
	 */
	private $plugin_name;

	/**
	 * The version of this plugin.
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      string    $version    The current version of this plugin.
	 */
	private $version;

	/**
	 * Initialize the class and set its properties.
	 *
	 * @since    1.0.0
	 * @param    string    $plugin_name       The name of the plugin.
	 * @param    string    $version    The version of this plugin.
	 */
	public function __construct( $plugin_name, $version ) {
		$this->plugin_name = $plugin_name;
		$this->version = $version;
	}

	/**
	 * Register the stylesheets for the public-facing side of the site.
	 *
	 * @since    1.0.0
	 */
	public function enqueue_styles() {
		/**
		 * This function is provided for demonstration purposes only.
		 *
		 * An instance of this class should be passed to the run() function
		 * defined in WP_Breach_Loader as all of the hooks are defined
		 * in that particular class.
		 *
		 * The WP_Breach_Loader will then create the relationship
		 * between the defined hooks and the functions defined in this
		 * class.
		 */

		wp_enqueue_style( $this->plugin_name, plugin_dir_url( __FILE__ ) . 'css/wp-breach-public.css', array(), $this->version, 'all' );
	}

	/**
	 * Register the JavaScript for the public-facing side of the site.
	 *
	 * @since    1.0.0
	 */
	public function enqueue_scripts() {
		/**
		 * This function is provided for demonstration purposes only.
		 *
		 * An instance of this class should be passed to the run() function
		 * defined in WP_Breach_Loader as all of the hooks are defined
		 * in that particular class.
		 *
		 * The WP_Breach_Loader will then create the relationship
		 * between the defined hooks and the functions defined in this
		 * class.
		 */

		wp_enqueue_script( $this->plugin_name, plugin_dir_url( __FILE__ ) . 'js/wp-breach-public.js', array( 'jquery' ), $this->version, false );

		// Localize script for AJAX (if needed for public-facing features)
		wp_localize_script( $this->plugin_name, 'wp_breach_public_ajax', array(
			'ajax_url' => admin_url( 'admin-ajax.php' ),
			'nonce'    => wp_create_nonce( 'wp_breach_public_nonce' ),
		) );
	}

	/**
	 * Add security headers to protect against common vulnerabilities
	 *
	 * @since    1.0.0
	 */
	public function add_security_headers() {
		// Only add headers if they're not already set and option is enabled
		$add_headers = get_option( 'wp_breach_add_security_headers', true );

		if ( ! $add_headers || headers_sent() ) {
			return;
		}

		// X-Content-Type-Options
		if ( ! headers_sent() && ! $this->header_already_sent( 'X-Content-Type-Options' ) ) {
			header( 'X-Content-Type-Options: nosniff' );
		}

		// X-Frame-Options
		if ( ! headers_sent() && ! $this->header_already_sent( 'X-Frame-Options' ) ) {
			header( 'X-Frame-Options: SAMEORIGIN' );
		}

		// X-XSS-Protection
		if ( ! headers_sent() && ! $this->header_already_sent( 'X-XSS-Protection' ) ) {
			header( 'X-XSS-Protection: 1; mode=block' );
		}

		// Referrer Policy
		if ( ! headers_sent() && ! $this->header_already_sent( 'Referrer-Policy' ) ) {
			header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		}
	}

	/**
	 * Check if a header has already been sent
	 *
	 * @since    1.0.0
	 * @param    string $header_name The header name to check
	 * @return   bool   True if header already sent, false otherwise
	 */
	private function header_already_sent( $header_name ) {
		$headers = headers_list();
		foreach ( $headers as $header ) {
			if ( stripos( $header, $header_name . ':' ) === 0 ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Monitor for suspicious activity on the frontend
	 *
	 * @since    1.0.0
	 */
	public function monitor_frontend_activity() {
		// Only monitor if option is enabled
		$monitor_enabled = get_option( 'wp_breach_frontend_monitoring', false );

		if ( ! $monitor_enabled ) {
			return;
		}

		// Monitor for suspicious parameters
		$this->check_suspicious_parameters();

		// Monitor for file inclusion attempts
		$this->check_file_inclusion_attempts();

		// Monitor for SQL injection attempts
		$this->check_sql_injection_attempts();
	}

	/**
	 * Check for suspicious parameters in request
	 *
	 * @since    1.0.0
	 */
	private function check_suspicious_parameters() {
		$suspicious_patterns = array(
			'/\.\.\//i',          // Directory traversal
			'/<script/i',         // XSS attempts
			'/javascript:/i',     // JavaScript protocols
			'/vbscript:/i',       // VBScript protocols
			'/onload=/i',         // Event handlers
			'/onerror=/i',        // Event handlers
			'/eval\(/i',          // Code execution
			'/base64_decode/i',   // Base64 decoding
			'/gzinflate/i',       // Compression functions
		);

		$request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field($_SERVER['REQUEST_URI']) : '';
		$query_string = isset($_SERVER['QUERY_STRING']) ? sanitize_text_field($_SERVER['QUERY_STRING']) : '';

		foreach ( $suspicious_patterns as $pattern ) {
			if ( preg_match( $pattern, $request_uri ) || preg_match( $pattern, $query_string ) ) {
				$this->log_security_event( 'suspicious_parameter', array(
					'pattern'      => $pattern,
					'request_uri'  => $request_uri,
					'query_string' => $query_string,
					'user_agent'   => sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ?? '' ),
					'ip_address'   => $this->get_client_ip(),
				) );
				break;
			}
		}
	}

	/**
	 * Check for file inclusion attempts
	 *
	 * @since    1.0.0
	 */
	private function check_file_inclusion_attempts() {
		$inclusion_patterns = array(
			'/include\s*\(/i',
			'/require\s*\(/i',
			'/file_get_contents\s*\(/i',
			'/fopen\s*\(/i',
			'/readfile\s*\(/i',
		);

		$request_data = array_merge( $_GET, $_POST );

		foreach ( $request_data as $key => $value ) {
			if ( is_string( $value ) ) {
				foreach ( $inclusion_patterns as $pattern ) {
					if ( preg_match( $pattern, $value ) ) {
						$this->log_security_event( 'file_inclusion_attempt', array(
							'parameter' => $key,
							'value'     => $value,
							'pattern'   => $pattern,
							'ip_address' => $this->get_client_ip(),
						) );
						break 2;
					}
				}
			}
		}
	}

	/**
	 * Check for SQL injection attempts
	 *
	 * @since    1.0.0
	 */
	private function check_sql_injection_attempts() {
		$sql_patterns = array(
			'/union\s+select/i',
			'/select\s+.*\s+from/i',
			'/insert\s+into/i',
			'/update\s+.*\s+set/i',
			'/delete\s+from/i',
			'/drop\s+table/i',
			'/or\s+1\s*=\s*1/i',
			'/and\s+1\s*=\s*1/i',
		);

		$request_data = array_merge( $_GET, $_POST );

		foreach ( $request_data as $key => $value ) {
			if ( is_string( $value ) ) {
				foreach ( $sql_patterns as $pattern ) {
					if ( preg_match( $pattern, $value ) ) {
						$this->log_security_event( 'sql_injection_attempt', array(
							'parameter'  => $key,
							'value'      => $value,
							'pattern'    => $pattern,
							'ip_address' => $this->get_client_ip(),
						) );
						break 2;
					}
				}
			}
		}
	}

	/**
	 * Log security events
	 *
	 * @since    1.0.0
	 * @param    string $event_type Type of security event
	 * @param    array  $event_data Event data to log
	 */
	private function log_security_event( $event_type, $event_data ) {
		$log_entry = array(
			'timestamp'  => current_time( 'mysql' ),
			'event_type' => $event_type,
			'event_data' => $event_data,
			'severity'   => $this->get_event_severity( $event_type ),
		);

		// Store in transient for immediate access
		$recent_events = get_transient( 'wp_breach_recent_security_events' );
		if ( ! is_array( $recent_events ) ) {
			$recent_events = array();
		}

		$recent_events[] = $log_entry;

		// Keep only last 100 events in transient
		if ( count( $recent_events ) > 100 ) {
			$recent_events = array_slice( $recent_events, -100 );
		}

		set_transient( 'wp_breach_recent_security_events', $recent_events, HOUR_IN_SECONDS );

		// Also log to WordPress error log if enabled
		if ( get_option( 'wp_breach_log_to_error_log', false ) && function_exists( 'error_log' ) ) {
			error_log( sprintf(
				'WP-Breach Security Event: %s - %s',
				$event_type,
				wp_json_encode( $event_data )
			) );
		}
	}

	/**
	 * Get event severity level
	 *
	 * @since    1.0.0
	 * @param    string $event_type Type of security event
	 * @return   string Severity level (low, medium, high, critical)
	 */
	private function get_event_severity( $event_type ) {
		$severity_map = array(
			'suspicious_parameter'     => 'medium',
			'file_inclusion_attempt'   => 'high',
			'sql_injection_attempt'    => 'critical',
			'xss_attempt'             => 'high',
			'directory_traversal'     => 'high',
		);

		return $severity_map[ $event_type ] ?? 'low';
	}

	/**
	 * Get client IP address
	 *
	 * @since    1.0.0
	 * @return   string Client IP address
	 */
	private function get_client_ip() {
		$ip_keys = array(
			'HTTP_CF_CONNECTING_IP',
			'HTTP_CLIENT_IP',
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_FORWARDED',
			'HTTP_X_CLUSTER_CLIENT_IP',
			'HTTP_FORWARDED_FOR',
			'HTTP_FORWARDED',
			'REMOTE_ADDR',
		);

		foreach ( $ip_keys as $key ) {
			if ( array_key_exists( $key, $_SERVER ) === true ) {
				foreach ( explode( ',', $_SERVER[ $key ] ) as $ip ) {
					$ip = trim( $ip );

					if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) !== false ) {
						return $ip;
					}
				}
			}
		}

		return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
	}

	/**
	 * Handle public AJAX requests
	 *
	 * @since    1.0.0
	 */
	public function handle_public_ajax() {
		// Verify nonce
		if ( ! wp_verify_nonce( $_POST['nonce'] ?? '', 'wp_breach_public_nonce' ) ) {
			wp_die( 'Security check failed' );
		}

		$action = sanitize_text_field( $_POST['action'] ?? '' );

		switch ( $action ) {
			case 'wp_breach_report_security_issue':
				$this->ajax_report_security_issue();
				break;
			default:
				wp_send_json_error( array( 'message' => __( 'Invalid action', 'wp-breach' ) ) );
		}
	}

	/**
	 * AJAX handler for reporting security issues from frontend
	 *
	 * @since    1.0.0
	 */
	private function ajax_report_security_issue() {
		$issue_description = sanitize_textarea_field( $_POST['issue_description'] ?? '' );
		$issue_url = esc_url_raw( $_POST['issue_url'] ?? '' );

		if ( empty( $issue_description ) ) {
			wp_send_json_error( array( 'message' => __( 'Issue description is required', 'wp-breach' ) ) );
		}

		// Log the reported issue
		$this->log_security_event( 'user_reported_issue', array(
			'description' => $issue_description,
			'url'         => $issue_url,
			'ip_address'  => $this->get_client_ip(),
			'user_agent'  => $_SERVER['HTTP_USER_AGENT'] ?? '',
		) );

		wp_send_json_success( array( 'message' => __( 'Thank you for reporting the security issue', 'wp-breach' ) ) );
	}

	/**
	 * Add shortcodes for public functionality
	 *
	 * @since    1.0.0
	 */
	public function add_shortcodes() {
		add_shortcode( 'wp_breach_security_status', array( $this, 'shortcode_security_status' ) );
		add_shortcode( 'wp_breach_report_form', array( $this, 'shortcode_report_form' ) );
	}

	/**
	 * Security status shortcode
	 *
	 * @since    1.0.0
	 * @param    array $atts Shortcode attributes
	 * @return   string Shortcode output
	 */
	public function shortcode_security_status( $atts ) {
		$atts = shortcode_atts( array(
			'show_details' => 'false',
		), $atts, 'wp_breach_security_status' );

		$show_details = $atts['show_details'] === 'true';

		ob_start();
		include plugin_dir_path( __FILE__ ) . 'partials/wp-breach-public-security-status.php';
		return ob_get_clean();
	}

	/**
	 * Security report form shortcode
	 *
	 * @since    1.0.0
	 * @param    array $atts Shortcode attributes
	 * @return   string Shortcode output
	 */
	public function shortcode_report_form( $atts ) {
		$atts = shortcode_atts( array(
			'title' => __( 'Report Security Issue', 'wp-breach' ),
		), $atts, 'wp_breach_report_form' );

		ob_start();
		include plugin_dir_path( __FILE__ ) . 'partials/wp-breach-public-report-form.php';
		return ob_get_clean();
	}
}
