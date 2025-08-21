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
	 * @param    string    $plugin_name       The name of this plugin.
	 * @param    string    $version    The version of this plugin.
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

		wp_enqueue_style( $this->plugin_name, plugin_dir_url( __FILE__ ) . 'css/wp-breach-admin.css', array(), $this->version, 'all' );
	}

	/**
	 * Register the JavaScript for the admin area.
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

		wp_enqueue_script( $this->plugin_name, plugin_dir_url( __FILE__ ) . 'js/wp-breach-admin.js', array( 'jquery' ), $this->version, false );

		// Localize script for AJAX
		wp_localize_script( $this->plugin_name, 'wp_breach_ajax', array(
			'ajax_url' => admin_url( 'admin-ajax.php' ),
			'nonce'    => wp_create_nonce( 'wp_breach_ajax_nonce' ),
		) );
	}

	/**
	 * Add admin menu pages
	 *
	 * @since    1.0.0
	 */
	public function add_admin_menu() {
		// Main menu page
		add_menu_page(
			__( 'WP-Breach Security', 'wp-breach' ),
			__( 'WP-Breach', 'wp-breach' ),
			'wp_breach_view_vulnerabilities',
			'wp-breach',
			array( $this, 'display_dashboard_page' ),
			'dashicons-shield',
			30
		);

		// Dashboard submenu (same as main menu)
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

		// Quick Fix submenu
		add_submenu_page(
			'wp-breach',
			__( 'Quick Fix', 'wp-breach' ),
			__( 'Quick Fix', 'wp-breach' ),
			'wp_breach_apply_fixes',
			'wp-breach-quick-fix',
			array( $this, 'display_quick_fix_page' )
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

		// Reports submenu
		add_submenu_page(
			'wp-breach',
			__( 'Reports', 'wp-breach' ),
			__( 'Reports', 'wp-breach' ),
			'wp_breach_view_reports',
			'wp-breach-reports',
			array( $this, 'display_reports_page' )
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

		// Settings submenu
		add_submenu_page(
			'wp-breach',
			__( 'Settings', 'wp-breach' ),
			__( 'Settings', 'wp-breach' ),
			'wp_breach_manage_settings',
			'wp-breach-settings',
			array( $this, 'display_settings_page' )
		);
	}

	/**
	 * Display the dashboard page
	 *
	 * @since    1.0.0
	 */
	public function display_dashboard_page() {
		$partial_file = plugin_dir_path( __FILE__ ) . 'partials/wp-breach-admin-dashboard.php';
		if ( file_exists( $partial_file ) ) {
			include_once $partial_file;
		} else {
			$this->display_placeholder_page( 'Dashboard', 'The dashboard interface will be available in Issue #004.' );
		}
	}

	/**
	 * Display the vulnerabilities page
	 *
	 * @since    1.0.0
	 */
	public function display_vulnerabilities_page() {
		$partial_file = plugin_dir_path( __FILE__ ) . 'partials/wp-breach-admin-vulnerabilities.php';
		if ( file_exists( $partial_file ) ) {
			include_once $partial_file;
		} else {
			$this->display_placeholder_page( 'Vulnerabilities', 'The vulnerabilities interface will be available in Issue #004.' );
		}
	}

	/**
	 * Display the quick fix page
	 *
	 * @since    1.0.0
	 */
	public function display_quick_fix_page() {
		$partial_file = plugin_dir_path( __FILE__ ) . 'partials/wp-breach-admin-quick-fix.php';
		if ( file_exists( $partial_file ) ) {
			include_once $partial_file;
		} else {
			$this->display_placeholder_page( 'Quick Fix', 'The quick fix interface will be available in Issue #004.' );
		}
	}

	/**
	 * Display the monitoring page
	 *
	 * @since    1.0.0
	 */
	public function display_monitoring_page() {
		$partial_file = plugin_dir_path( __FILE__ ) . 'partials/wp-breach-admin-monitoring.php';
		if ( file_exists( $partial_file ) ) {
			include_once $partial_file;
		} else {
			$this->display_placeholder_page( 'Monitoring', 'The monitoring interface will be available in Issue #004.' );
		}
	}

	/**
	 * Display the reports page
	 *
	 * @since    1.0.0
	 */
	public function display_reports_page() {
		$partial_file = plugin_dir_path( __FILE__ ) . 'partials/wp-breach-admin-reports.php';
		if ( file_exists( $partial_file ) ) {
			include_once $partial_file;
		} else {
			$this->display_placeholder_page( 'Reports', 'The reports interface will be available in Issue #004.' );
		}
	}

	/**
	 * Display the alerts page
	 *
	 * @since    1.0.0
	 */
	public function display_alerts_page() {
		$partial_file = plugin_dir_path( __FILE__ ) . 'partials/wp-breach-admin-alerts.php';
		if ( file_exists( $partial_file ) ) {
			include_once $partial_file;
		} else {
			$this->display_placeholder_page( 'Alerts', 'The alerts interface will be available in Issue #004.' );
		}
	}

	/**
	 * Display the settings page
	 *
	 * @since    1.0.0
	 */
	public function display_settings_page() {
		$partial_file = plugin_dir_path( __FILE__ ) . 'partials/wp-breach-admin-settings.php';
		if ( file_exists( $partial_file ) ) {
			include_once $partial_file;
		} else {
			$this->display_placeholder_page( 'Settings', 'The settings interface will be available in Issue #004.' );
		}
	}

	/**
	 * Display placeholder page for admin interfaces not yet implemented
	 *
	 * @since    1.0.0
	 * @param    string   $page_title    Title of the page
	 * @param    string   $message       Message to display
	 */
	private function display_placeholder_page( $page_title, $message ) {
		?>
		<div class="wrap">
			<h1><?php echo esc_html( 'WP-Breach ' . $page_title ); ?></h1>
			<div class="notice notice-info">
				<p><strong><?php echo esc_html( $message ); ?></strong></p>
			</div>
		</div>
		<?php
	}

	/**
	 * Add admin notices
	 *
	 * @since    1.0.0
	 */
	public function add_admin_notices() {
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
	 * Get pending vulnerabilities count
	 *
	 * @since    1.0.0
	 * @return   int Number of pending vulnerabilities
	 */
	private function get_pending_vulnerabilities_count() {
		try {
			$database = ( new WP_Breach() )->get_database();
			$vulnerability_model = $database->get_vulnerability_model();
			return $vulnerability_model->get_vulnerability_count( array( 'status' => 'active' ) );
		} catch ( Exception $e ) {
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

		$wp_admin_bar->add_node( array(
			'id'     => 'wp-breach-dashboard',
			'parent' => 'wp-breach',
			'title'  => __( 'Dashboard', 'wp-breach' ),
			'href'   => admin_url( 'admin.php?page=wp-breach' ),
		) );

		$wp_admin_bar->add_node( array(
			'id'     => 'wp-breach-vulnerabilities',
			'parent' => 'wp-breach',
			'title'  => __( 'Vulnerabilities', 'wp-breach' ),
			'href'   => admin_url( 'admin.php?page=wp-breach-vulnerabilities' ),
		) );

		$wp_admin_bar->add_node( array(
			'id'     => 'wp-breach-quick-scan',
			'parent' => 'wp-breach',
			'title'  => __( 'Run Quick Scan', 'wp-breach' ),
			'href'   => wp_nonce_url( admin_url( 'admin.php?page=wp-breach&action=quick-scan' ), 'wp_breach_quick_scan' ),
		) );
	}

	/**
	 * Handle AJAX requests
	 *
	 * @since    1.0.0
	 */
	public function handle_ajax_requests() {
		// Verify nonce
		if ( ! ( is_array( $_POST ) && isset( $_POST['nonce'] ) && wp_verify_nonce( $_POST['nonce'], 'wp_breach_ajax_nonce' ) ) ) {
			wp_die( 'Security check failed' );
		}

		$action = sanitize_text_field( $_POST['action'] ?? '' );

		switch ( $action ) {
			case 'wp_breach_quick_scan':
				$this->ajax_quick_scan();
				break;
			case 'wp_breach_get_scan_status':
				$this->ajax_get_scan_status();
				break;
			case 'wp_breach_dismiss_vulnerability':
				$this->ajax_dismiss_vulnerability();
				break;
			default:
				wp_send_json_error( array( 'message' => __( 'Invalid action', 'wp-breach' ) ) );
		}
	}

	/**
	 * AJAX handler for quick scan
	 *
	 * @since    1.0.0
	 */
	private function ajax_quick_scan() {
		// Check capabilities
		if ( ! current_user_can( 'wp_breach_run_scans' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions', 'wp-breach' ) ) );
		}

		try {
			// Load scanner class
			require_once WP_BREACH_PLUGIN_DIR . 'includes/scanners/class-wp-breach-scanner.php';
			
			$scanner = new WP_Breach_Scanner();
			$scan_result = $scanner->start_quick_scan();
			
			if ( $scan_result && isset( $scan_result['scan_id'] ) ) {
				wp_send_json_success( array( 
					'message' => __( 'Quick scan initiated successfully', 'wp-breach' ),
					'scan_id' => $scan_result['scan_id']
				) );
			} else {
				wp_send_json_error( array( 'message' => __( 'Failed to start scan', 'wp-breach' ) ) );
			}
		} catch ( Exception $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}
	}

	/**
	 * AJAX handler for getting scan status
	 *
	 * @since    1.0.0
	 */
	private function ajax_get_scan_status() {
		// Check capabilities
		if ( ! current_user_can( 'wp_breach_view_vulnerabilities' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions', 'wp-breach' ) ) );
		}

		try {
			$database = ( new WP_Breach() )->get_database();
			$scan_model = $database->get_scan_model();
			$current_scan = $scan_model->get_current_scan();
			
			if ( $current_scan ) {
				$progress = $scan_model->get_scan_progress( $current_scan['id'] );
				wp_send_json_success( array(
					'status' => $current_scan['status'],
					'progress' => $progress,
					'message' => sprintf( __( 'Scan in progress: %s', 'wp-breach' ), $progress['current_step'] ?? '' )
				) );
			} else {
				wp_send_json_success( array(
					'status' => 'idle',
					'message' => __( 'No scan in progress', 'wp-breach' )
				) );
			}
		} catch ( Exception $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}
	}

	/**
	 * AJAX handler for dismissing vulnerability
	 *
	 * @since    1.0.0
	 */
	private function ajax_dismiss_vulnerability() {
		// Check capabilities
		if ( ! current_user_can( 'wp_breach_view_vulnerabilities' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions', 'wp-breach' ) ) );
		}

		$vulnerability_id = intval( $_POST['vulnerability_id'] ?? 0 );

		if ( $vulnerability_id <= 0 ) {
			wp_send_json_error( array( 'message' => __( 'Invalid vulnerability ID', 'wp-breach' ) ) );
		}

		try {
			$database = ( new WP_Breach() )->get_database();
			$vulnerability_model = $database->get_vulnerability_model();
			
			$result = $vulnerability_model->update_vulnerability( $vulnerability_id, array( 'status' => 'dismissed' ) );
			
			if ( $result ) {
				wp_send_json_success( array( 'message' => __( 'Vulnerability dismissed successfully', 'wp-breach' ) ) );
			} else {
				wp_send_json_error( array( 'message' => __( 'Failed to dismiss vulnerability', 'wp-breach' ) ) );
			}
		} catch ( Exception $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}
	}

	/**
	 * Add dashboard widgets
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
	 * Display dashboard widget
	 *
	 * @since    1.0.0
	 */
	public function display_dashboard_widget() {
		$widget_file = plugin_dir_path( __FILE__ ) . 'partials/wp-breach-admin-dashboard-widget.php';
		if ( file_exists( $widget_file ) ) {
			include_once $widget_file;
		} else {
			// Display simple widget content for Issue #002
			echo '<div class="wp-breach-widget">';
			echo '<p><strong>WP-Breach Security Status</strong></p>';
			echo '<p>✅ Database layer implemented (Issue #002 complete)</p>';
			echo '<p>⏳ Admin interface coming in Issue #004</p>';
			echo '</div>';
		}
	}
}
