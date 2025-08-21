<?php
/**
 * WP-Breach Security Plugin
 *
 * @package     WP_Breach
 * @author      luozongbao <luo.zongbao@outlook.com>
 * @copyright   2025 luozongbao
 * @license     GPL-2.0+
 *
 * @wordpress-plugin
 * Plugin Name:         WP-Breach
 * Plugin URI:          https://github.com/luozongbao/wp-breach
 * Description:         Comprehensive WordPress security plugin that scans websites for vulnerabilities across all security levels and provides actionable suggestions or automated fixes for identified security issues.
 * Version:             1.0.0
 * Requires at least:   5.0
 * Requires PHP:        7.4
 * Author:              luozongbao
 * Author URI:          https://github.com/luozongbao
 * Text Domain:         wp-breach
 * Domain Path:         /languages
 * License:             GPL v2 or later
 * License URI:         https://www.gnu.org/licenses/gpl-2.0.html
 * Network:             false
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Currently plugin version.
 * Start at version 1.0.0 and use SemVer - https://semver.org
 * Rename this for your plugin and update it as you release new versions.
 */
define( 'WP_BREACH_VERSION', '1.0.0' );

/**
 * Plugin constants
 */
define( 'WP_BREACH_PLUGIN_FILE', __FILE__ );
define( 'WP_BREACH_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WP_BREACH_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'WP_BREACH_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );

/**
 * The code that runs during plugin activation.
 * This action is documented in includes/class-wp-breach-activator.php
 */
function activate_wp_breach() {
	require_once WP_BREACH_PLUGIN_DIR . 'includes/class-wp-breach-activator.php';
	WP_Breach_Activator::activate();
}

/**
 * The code that runs during plugin deactivation.
 * This action is documented in includes/class-wp-breach-deactivator.php
 */
function deactivate_wp_breach() {
	require_once WP_BREACH_PLUGIN_DIR . 'includes/class-wp-breach-deactivator.php';
	WP_Breach_Deactivator::deactivate();
}

register_activation_hook( __FILE__, 'activate_wp_breach' );
register_deactivation_hook( __FILE__, 'deactivate_wp_breach' );

/**
 * The core plugin class that is used to define internationalization,
 * admin-specific hooks, and public-facing site hooks.
 */
require WP_BREACH_PLUGIN_DIR . 'includes/class-wp-breach.php';

/**
 * Begins execution of the plugin.
 *
 * Since everything within the plugin is registered via hooks,
 * then kicking off the plugin from this point in the file does
 * not affect the page life cycle.
 *
 * @since    1.0.0
 */
function run_wp_breach() {
	$plugin = new WP_Breach();
	$plugin->run();
}
run_wp_breach();

// Load database test file if in debug mode
if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
	$test_file = WP_BREACH_PLUGIN_DIR . 'database-test.php';
	if ( file_exists( $test_file ) ) {
		require_once $test_file;
	}
	
	$scanner_test_file = WP_BREACH_PLUGIN_DIR . 'scanner-test.php';
	if ( file_exists( $scanner_test_file ) ) {
		require_once $scanner_test_file;
	}
}
