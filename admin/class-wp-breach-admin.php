<?php
/**
 * The admin-specific functionality of the plugin.
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/admin
 */

/**
 * The admin-specific functionality of the plugin.
 *
 * Defines the plugin name, version, and hooks for the admin area.
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/admin
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Admin {

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
	 * @param      string    $plugin_name       The name of this plugin.
	 * @param      string    $version    The version of this plugin.
	 */
	public function __construct( $plugin_name, $version ) {
		$this->plugin_name = $plugin_name;
		$this->version = $version;
	}

	/**
	 * Register the stylesheets for the admin area.
	 *
	 * @since    1.0.0
	 */
	public function enqueue_styles() {
		wp_enqueue_style( $this->plugin_name, plugin_dir_url( __FILE__ ) . 'css/wp-breach-admin.css', array(), $this->version, 'all' );
	}

	/**
	 * Register the JavaScript for the admin area.
	 *
	 * @since    1.0.0
	 */
	public function enqueue_scripts() {
		wp_enqueue_script( $this->plugin_name, plugin_dir_url( __FILE__ ) . 'js/wp-breach-admin.js', array( 'jquery' ), $this->version, false );
		
		// Localize script for AJAX
		wp_localize_script( $this->plugin_name, 'wp_breach_ajax', array(
			'ajax_url' => admin_url( 'admin-ajax.php' ),
			'nonce'    => wp_create_nonce( 'wp_breach_nonce' ),
		) );
	}

	/**
	 * Add admin menu pages.
	 *
	 * @since    1.0.0
	 */
	public function add_admin_menu() {
		// Main menu page
		add_menu_page(
			__( 'WP-Breach', 'wp-breach' ),
			__( 'WP-Breach', 'wp-breach' ),
			'wp_breach_view_vulnerabilities',
			'wp-breach',
			array( $this, 'display_dashboard_page' ),
			'dashicons-shield',
			30
		);

		// Dashboard submenu
		add_submenu_page(
			'wp-breach',
			__( 'Dashboard', 'wp-breach' ),
			__( 'Dashboard', 'wp-breach' ),
			'wp_breach_view_vulnerabilities',
			'wp-breach',
			array( $this, 'display_dashboard_page' )
		);

		// Vulnerabilities submenu
		add_submenu_page(
			'wp-breach',
			__( 'Vulnerabilities', 'wp-breach' ),
			__( 'Vulnerabilities', 'wp-breach' ),
			'wp_breach_view_vulnerabilities',
			'wp-breach-vulnerabilities',
			array( $this, 'display_vulnerabilities_page' )
		);

		// Settings submenu
		add_submenu_page(
			'wp-breach',
			__( 'Settings', 'wp-breach' ),
			__( 'Settings', 'wp-breach' ),
			'wp_breach_view_vulnerabilities',
			'wp-breach-settings',
			array( $this, 'display_settings_page' )
		);

		// Reports submenu
		add_submenu_page(
			'wp-breach',
			__( 'Reports', 'wp-breach' ),
			__( 'Reports', 'wp-breach' ),
			'wp_breach_view_vulnerabilities',
			'wp-breach-reports',
			array( $this, 'display_reports_page' )
		);

		// Monitoring submenu
		add_submenu_page(
			'wp-breach',
			__( 'Monitoring', 'wp-breach' ),
			__( 'Monitoring', 'wp-breach' ),
			'wp_breach_view_vulnerabilities',
			'wp-breach-monitoring',
			array( $this, 'display_monitoring_page' )
		);

		// Quick Fix submenu
		add_submenu_page(
			'wp-breach',
			__( 'Quick Fix', 'wp-breach' ),
			__( 'Quick Fix', 'wp-breach' ),
			'wp_breach_view_vulnerabilities',
			'wp-breach-quick-fix',
			array( $this, 'display_quick_fix_page' )
		);

		// Alerts submenu
		add_submenu_page(
			'wp-breach',
			__( 'Alerts', 'wp-breach' ),
			__( 'Alerts', 'wp-breach' ),
			'wp_breach_view_vulnerabilities',
			'wp-breach-alerts',
			array( $this, 'display_alerts_page' )
		);
	}

	/**
	 * Get count of pending vulnerabilities for admin bar display.
	 *
	 * @since    1.0.0
	 * @return   int    Number of pending vulnerabilities.
	 */
	private function get_pending_vulnerabilities_count() {
		try {
			// Check if the main plugin class exists and is available
			if ( ! class_exists( 'WP_Breach' ) ) {
				return 0;
			}

			$plugin = new WP_Breach();
			
			// Check if plugin is properly initialized
			if ( ! $plugin || ! method_exists( $plugin, 'get_database' ) ) {
				return 0;
			}

			$database = $plugin->get_database();
			
			// Check if database is available
			if ( ! $database || ! method_exists( $database, 'get_vulnerability_model' ) ) {
				return 0;
			}

			$vulnerability_model = $database->get_vulnerability_model();
			
			// Check if vulnerability model is available
			if ( ! $vulnerability_model || ! method_exists( $vulnerability_model, 'get_vulnerability_count' ) ) {
				return 0;
			}

			return $vulnerability_model->get_vulnerability_count( array( 'status' => 'active' ) );
		} catch ( Exception $e ) {
			// Log error for debugging
			error_log( 'WP-Breach: Error getting vulnerability count: ' . $e->getMessage() );
			return 0;
		} catch ( Error $e ) {
			// Handle PHP 7+ Error class
			error_log( 'WP-Breach: Fatal error getting vulnerability count: ' . $e->getMessage() );
			return 0;
		}
	}

	/**
	 * Add admin bar menu
	 *
	 * @since    1.0.0
	 * @param    WP_Admin_Bar $wp_admin_bar The admin bar object
	 */
	public function add_admin_bar_menu( $wp_admin_bar ) {
		// Only show to users with appropriate capabilities
		if ( ! current_user_can( 'wp_breach_view_vulnerabilities' ) ) {
			return;
		}

		$pending_count = $this->get_pending_vulnerabilities_count();
		$title = __( 'WP-Breach', 'wp-breach' );

		if ( $pending_count > 0 ) {
			$title .= ' <span class="ab-label awaiting-mod">' . $pending_count . '</span>';
		}

		$wp_admin_bar->add_node( array(
			'id'    => 'wp-breach',
			'title' => $title,
			'href'  => admin_url( 'admin.php?page=wp-breach' ),
		) );

		// Add sub-items
		$wp_admin_bar->add_node( array(
			'id'     => 'wp-breach-dashboard',
			'parent' => 'wp-breach',
			'title'  => __( 'Dashboard', 'wp-breach' ),
			'href'   => admin_url( 'admin.php?page=wp-breach' ),
		) );

		$wp_admin_bar->add_node( array(
			'id'     => 'wp-breach-scan',
			'parent' => 'wp-breach',
			'title'  => __( 'Run Scan', 'wp-breach' ),
			'href'   => admin_url( 'admin.php?page=wp-breach-monitoring' ),
		) );

		if ( $pending_count > 0 ) {
			$wp_admin_bar->add_node( array(
				'id'     => 'wp-breach-vulnerabilities',
				'parent' => 'wp-breach',
				'title'  => sprintf( __( 'Vulnerabilities (%d)', 'wp-breach' ), $pending_count ),
				'href'   => admin_url( 'admin.php?page=wp-breach-vulnerabilities' ),
			) );
		}
	}

	/**
	 * Display the dashboard page.
	 *
	 * @since    1.0.0
	 */
	public function display_dashboard_page() {
		include_once plugin_dir_path( __FILE__ ) . 'partials/wp-breach-admin-dashboard.php';
	}

	/**
	 * Display the vulnerabilities page.
	 *
	 * @since    1.0.0
	 */
	public function display_vulnerabilities_page() {
		include_once plugin_dir_path( __FILE__ ) . 'partials/wp-breach-admin-vulnerabilities.php';
	}

	/**
	 * Display the settings page.
	 *
	 * @since    1.0.0
	 */
	public function display_settings_page() {
		include_once plugin_dir_path( __FILE__ ) . 'partials/wp-breach-admin-settings.php';
	}

	/**
	 * Display the reports page.
	 *
	 * @since    1.0.0
	 */
	public function display_reports_page() {
		include_once plugin_dir_path( __FILE__ ) . 'partials/wp-breach-admin-reports.php';
	}

	/**
	 * Display the monitoring page.
	 *
	 * @since    1.0.0
	 */
	public function display_monitoring_page() {
		include_once plugin_dir_path( __FILE__ ) . 'partials/wp-breach-admin-monitoring.php';
	}

	/**
	 * Display the quick fix page.
	 *
	 * @since    1.0.0
	 */
	public function display_quick_fix_page() {
		include_once plugin_dir_path( __FILE__ ) . 'partials/wp-breach-admin-quick-fix.php';
	}

	/**
	 * Display the alerts page.
	 *
	 * @since    1.0.0
	 */
	public function display_alerts_page() {
		include_once plugin_dir_path( __FILE__ ) . 'partials/wp-breach-admin-alerts.php';
	}

	/**
	 * Handle AJAX request for quick scan.
	 *
	 * @since    1.0.0
	 */
	public function ajax_quick_scan() {
		// Verify nonce
		if ( ! wp_verify_nonce( $_POST['nonce'], 'wp_breach_nonce' ) ) {
			wp_die( __( 'Security check failed', 'wp-breach' ) );
		}

		// Check capabilities
		if ( ! current_user_can( 'wp_breach_run_scans' ) ) {
			wp_die( __( 'Insufficient permissions', 'wp-breach' ) );
		}

		try {
			$database = ( new WP_Breach() )->get_database();
			$scan_model = $database->get_scan_model();
			
			// Create a new quick scan
			$scan_id = $scan_model->create_scan( array(
				'scan_type' => 'quick',
				'status'    => 'running',
				'started_by' => get_current_user_id(),
			) );

			if ( $scan_id ) {
				wp_send_json_success( array(
					'message' => __( 'Quick scan started successfully', 'wp-breach' ),
					'scan_id' => $scan_id,
				) );
			} else {
				wp_send_json_error( array(
					'message' => __( 'Failed to start scan', 'wp-breach' ),
				) );
			}
		} catch ( Exception $e ) {
			wp_send_json_error( array(
				'message' => __( 'Error starting scan: ', 'wp-breach' ) . $e->getMessage(),
			) );
		}
	}

	/**
	 * Handle AJAX request for scan status.
	 *
	 * @since    1.0.0
	 */
	public function ajax_scan_status() {
		// Verify nonce
		if ( ! wp_verify_nonce( $_POST['nonce'], 'wp_breach_nonce' ) ) {
			wp_die( __( 'Security check failed', 'wp-breach' ) );
		}

		// Check capabilities
		if ( ! current_user_can( 'wp_breach_view_vulnerabilities' ) ) {
			wp_die( __( 'Insufficient permissions', 'wp-breach' ) );
		}

		$scan_id = intval( $_POST['scan_id'] );

		try {
			$database = ( new WP_Breach() )->get_database();
			$scan_model = $database->get_scan_model();
			
			$scan = $scan_model->get( $scan_id );

			if ( $scan ) {
				wp_send_json_success( array(
					'status' => $scan->status,
					'progress' => $scan->progress,
					'completed_at' => $scan->completed_at,
					'vulnerabilities_found' => $scan->vulnerabilities_found,
				) );
			} else {
				wp_send_json_error( array(
					'message' => __( 'Scan not found', 'wp-breach' ),
				) );
			}
		} catch ( Exception $e ) {
			wp_send_json_error( array(
				'message' => __( 'Error getting scan status: ', 'wp-breach' ) . $e->getMessage(),
			) );
		}
	}

	/**
	 * Handle AJAX request for dismissing vulnerability.
	 *
	 * @since    1.0.0
	 */
	public function ajax_dismiss_vulnerability() {
		// Verify nonce
		if ( ! wp_verify_nonce( $_POST['nonce'], 'wp_breach_nonce' ) ) {
			wp_die( __( 'Security check failed', 'wp-breach' ) );
		}

		// Check capabilities
		if ( ! current_user_can( 'wp_breach_view_vulnerabilities' ) ) {
			wp_die( __( 'Insufficient permissions', 'wp-breach' ) );
		}

		$vulnerability_id = intval( $_POST['vulnerability_id'] );

		try {
			$database = ( new WP_Breach() )->get_database();
			$vulnerability_model = $database->get_vulnerability_model();
			
			$result = $vulnerability_model->update_vulnerability_status( 
				$vulnerability_id, 
				'dismissed',
				array( 'dismissed_by' => get_current_user_id() )
			);

			if ( $result ) {
				wp_send_json_success( array(
					'message' => __( 'Vulnerability dismissed successfully', 'wp-breach' ),
				) );
			} else {
				wp_send_json_error( array(
					'message' => __( 'Failed to dismiss vulnerability', 'wp-breach' ),
				) );
			}
		} catch ( Exception $e ) {
			wp_send_json_error( array(
				'message' => __( 'Error dismissing vulnerability: ', 'wp-breach' ) . $e->getMessage(),
			) );
		}
	}

	/**
	 * Add admin notices for important security alerts.
	 *
	 * @since    1.0.0
	 */
	public function add_admin_notices() {
		// Only show notices to users with appropriate capabilities
		if ( ! current_user_can( 'wp_breach_view_vulnerabilities' ) ) {
			return;
		}

		// Check for pending vulnerabilities
		$pending_vulnerabilities = $this->get_pending_vulnerabilities_count();
		if ( $pending_vulnerabilities > 0 ) {
			$message = sprintf(
				/* translators: %d: number of vulnerabilities */
				_n(
					'WP-Breach has detected %d vulnerability that requires your attention.',
					'WP-Breach has detected %d vulnerabilities that require your attention.',
					$pending_vulnerabilities,
					'wp-breach'
				),
				$pending_vulnerabilities
			);

			echo '<div class="notice notice-warning is-dismissible">';
			echo '<p><strong>' . esc_html( $message ) . '</strong></p>';
			echo '<p><a href="' . esc_url( admin_url( 'admin.php?page=wp-breach-vulnerabilities' ) ) . '" class="button button-primary">' . esc_html__( 'View Vulnerabilities', 'wp-breach' ) . '</a></p>';
			echo '</div>';
		}

		// Check for scan schedule
		if ( ! wp_next_scheduled( 'wp_breach_daily_scan' ) ) {
			echo '<div class="notice notice-error is-dismissible">';
			echo '<p><strong>' . esc_html__( 'WP-Breach automatic scanning is not scheduled. Please check your settings.', 'wp-breach' ) . '</strong></p>';
			echo '<p><a href="' . esc_url( admin_url( 'admin.php?page=wp-breach-settings' ) ) . '" class="button button-primary">' . esc_html__( 'Go to Settings', 'wp-breach' ) . '</a></p>';
			echo '</div>';
		}
	}

	/**
	 * Handle AJAX requests - Route to specific methods.
	 *
	 * @since    1.0.0
	 */
	public function handle_ajax_requests() {
		// Verify nonce
		if ( ! ( is_array( $_POST ) && isset( $_POST['nonce'] ) && wp_verify_nonce( $_POST['nonce'], 'wp_breach_nonce' ) ) ) {
			wp_die( 'Security check failed' );
		}

		$action = sanitize_text_field( $_POST['action'] ?? '' );

		switch ( $action ) {
			case 'wp_breach_quick_scan':
				$this->ajax_quick_scan();
				break;
			case 'wp_breach_get_scan_status':
				$this->ajax_scan_status();
				break;
			case 'wp_breach_dismiss_vulnerability':
				$this->ajax_dismiss_vulnerability();
				break;
			default:
				wp_send_json_error( array( 'message' => __( 'Invalid action', 'wp-breach' ) ) );
		}
	}

	/**
	 * Add dashboard widgets.
	 *
	 * @since    1.0.0
	 */
	public function add_dashboard_widgets() {
		// Only show to users with appropriate capabilities
		if ( ! current_user_can( 'wp_breach_view_vulnerabilities' ) ) {
			return;
		}

		wp_add_dashboard_widget(
			'wp_breach_security_overview',
			__( 'WP-Breach Security Overview', 'wp-breach' ),
			array( $this, 'display_dashboard_widget' )
		);
	}

	/**
	 * Display dashboard widget content.
	 *
	 * @since    1.0.0
	 */
	public function display_dashboard_widget() {
		$pending_vulnerabilities = $this->get_pending_vulnerabilities_count();
		
		echo '<div class="wp-breach-widget">';
		echo '<p><strong>' . __( 'WP-Breach Security Status', 'wp-breach' ) . '</strong></p>';
		
		if ( $pending_vulnerabilities > 0 ) {
			echo '<p style="color: #d63384;">⚠️ ' . sprintf( _n( '%d vulnerability detected', '%d vulnerabilities detected', $pending_vulnerabilities, 'wp-breach' ), $pending_vulnerabilities ) . '</p>';
			echo '<p><a href="' . esc_url( admin_url( 'admin.php?page=wp-breach-vulnerabilities' ) ) . '" class="button button-primary">' . __( 'View Details', 'wp-breach' ) . '</a></p>';
		} else {
			echo '<p style="color: #198754;">✅ ' . __( 'No active vulnerabilities detected', 'wp-breach' ) . '</p>';
			echo '<p><a href="' . esc_url( admin_url( 'admin.php?page=wp-breach-monitoring' ) ) . '" class="button">' . __( 'Run Scan', 'wp-breach' ) . '</a></p>';
		}
		
		echo '</div>';
	}
}
