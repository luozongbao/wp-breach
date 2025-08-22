<?php

/**
 * File Permissions Fix Strategy implementation.
 *
 * This class handles automated fixes for file and directory permission
 * vulnerabilities in WordPress installations.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/fixes/strategies
 */

/**
 * File Permissions Fix Strategy Class.
 *
 * Implements automated fixes for file permission vulnerabilities including:
 * - Incorrect file permissions (644 for files, 755 for directories)
 * - Overly permissive permissions (777, 666)
 * - WordPress-specific permission requirements
 * - Upload directory security
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/fixes/strategies
 * @author     WP Breach Team
 */
class WP_Breach_File_Permissions_Fix_Strategy implements WP_Breach_Fix_Strategy {

    /**
     * Supported vulnerability types.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $supported_types    Vulnerability types this strategy handles.
     */
    private $supported_types = array(
        'file_permissions',
        'directory_permissions',
        'permission_vulnerability',
        'access_control',
        'file_security',
        'upload_permissions'
    );

    /**
     * Recommended file permissions.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $recommended_permissions    Recommended permissions.
     */
    private $recommended_permissions = array(
        'files' => 0644,
        'directories' => 0755,
        'wp_config' => 0600,
        'htaccess' => 0644,
        'uploads' => 0755
    );

    /**
     * Dangerous permissions to fix.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $dangerous_permissions    Dangerous permission patterns.
     */
    private $dangerous_permissions = array(
        0777, // World writable
        0666, // World writable files
        0755  // For sensitive files like wp-config.php
    );

    /**
     * WordPress filesystem instance.
     *
     * @since    1.0.0
     * @access   private
     * @var      WP_Filesystem_Base    $filesystem    WordPress filesystem.
     */
    private $filesystem;

    /**
     * Permission changes made.
     *
     * @since    1.0.0
     * @access   private
     * @var      array    $permission_changes    Record of permission changes.
     */
    private $permission_changes = array();

    /**
     * Initialize the file permissions fix strategy.
     *
     * @since    1.0.0
     */
    public function __construct() {
        // Initialize WordPress filesystem
        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();
        global $wp_filesystem;
        $this->filesystem = $wp_filesystem;
    }

    /**
     * Check if this strategy can automatically fix the vulnerability.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   bool                       True if can auto-fix.
     */
    public function can_auto_fix($vulnerability) {
        // Check if vulnerability type is supported
        if (!in_array($vulnerability['type'], $this->supported_types)) {
            return false;
        }

        // Check if we have filesystem access
        if (!$this->filesystem || !$this->filesystem->exists(ABSPATH)) {
            return false;
        }

        // Check if we have permission to change permissions
        if (!$this->can_change_permissions()) {
            return false;
        }

        // Check if affected files exist and are accessible
        if (isset($vulnerability['affected_files'])) {
            foreach ($vulnerability['affected_files'] as $file) {
                if (!$this->filesystem->exists($file)) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Assess the safety of applying this fix.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Safety assessment.
     */
    public function assess_fix_safety($vulnerability) {
        $assessment = array(
            'safety_score' => 0.9, // Generally very safe
            'risk_factors' => array(),
            'requirements' => array(),
            'recommendations' => array()
        );

        // Check for potential risks
        if (isset($vulnerability['affected_files'])) {
            $critical_files = $this->identify_critical_files($vulnerability['affected_files']);
            if (!empty($critical_files)) {
                $assessment['risk_factors'][] = 'Critical files affected: ' . implode(', ', $critical_files);
                $assessment['safety_score'] -= 0.1;
            }
        }

        // Check server environment
        if (!$this->is_safe_environment()) {
            $assessment['risk_factors'][] = 'Shared hosting environment may have restrictions';
            $assessment['safety_score'] -= 0.05;
        }

        // Check if site is live
        if (!$this->is_development_environment()) {
            $assessment['risk_factors'][] = 'Permission changes on live site';
            $assessment['safety_score'] -= 0.05;
            $assessment['recommendations'][] = 'Test permission changes in staging first';
        }

        // Requirements
        $assessment['requirements'] = array(
            'filesystem_access' => $this->filesystem !== null,
            'permission_capability' => $this->can_change_permissions(),
            'file_access' => $this->can_access_affected_files($vulnerability)
        );

        return $assessment;
    }

    /**
     * Apply the automated fix.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Fix result.
     */
    public function apply_fix($vulnerability) {
        $result = array(
            'success' => false,
            'actions_taken' => array(),
            'changes_made' => array(),
            'rollback_data' => array(),
            'error_message' => ''
        );

        try {
            // Create backup of current permissions
            $permissions_backup = $this->create_permissions_backup($vulnerability);
            $result['rollback_data'] = $permissions_backup;

            // Apply permission fixes based on vulnerability type
            switch ($vulnerability['type']) {
                case 'file_permissions':
                    $fix_result = $this->fix_file_permissions($vulnerability);
                    break;
                
                case 'directory_permissions':
                    $fix_result = $this->fix_directory_permissions($vulnerability);
                    break;
                
                case 'upload_permissions':
                    $fix_result = $this->fix_upload_permissions($vulnerability);
                    break;
                
                default:
                    $fix_result = $this->fix_generic_permissions($vulnerability);
                    break;
            }

            if ($fix_result['success']) {
                $result['success'] = true;
                $result['actions_taken'] = array_merge($result['actions_taken'], $fix_result['actions_taken']);
                $result['changes_made'] = array_merge($result['changes_made'], $fix_result['changes_made']);
            } else {
                throw new Exception($fix_result['error_message']);
            }

        } catch (Exception $e) {
            $result['error_message'] = $e->getMessage();
            
            // Attempt to rollback if we have backup data
            if (!empty($result['rollback_data'])) {
                $this->rollback_fix($vulnerability, $result['rollback_data']);
            }
        }

        return $result;
    }

    /**
     * Validate that the fix was applied successfully.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @param    array    $fix_result       Fix application result.
     * @return   array                      Validation result.
     */
    public function validate_fix($vulnerability, $fix_result) {
        $validation = array(
            'is_valid' => false,
            'confidence' => 0,
            'validation_tests' => array(),
            'issues_found' => array()
        );

        try {
            // Validate permissions based on vulnerability type
            switch ($vulnerability['type']) {
                case 'file_permissions':
                    $validation = $this->validate_file_permissions($vulnerability, $fix_result);
                    break;
                
                case 'directory_permissions':
                    $validation = $this->validate_directory_permissions($vulnerability, $fix_result);
                    break;
                
                case 'upload_permissions':
                    $validation = $this->validate_upload_permissions($vulnerability, $fix_result);
                    break;
                
                default:
                    $validation = $this->validate_generic_permissions($vulnerability, $fix_result);
                    break;
            }

            // Test site functionality after permission changes
            $functionality_test = $this->test_site_functionality();
            $validation['validation_tests']['site_functionality'] = $functionality_test;
            
            if (!$functionality_test['passed']) {
                $validation['issues_found'][] = 'Site functionality affected by permission changes';
                $validation['confidence'] -= 30;
            }

            // Test file upload functionality if uploads directory was affected
            if ($this->was_uploads_affected($vulnerability)) {
                $upload_test = $this->test_upload_functionality();
                $validation['validation_tests']['upload_functionality'] = $upload_test;
                
                if (!$upload_test['passed']) {
                    $validation['issues_found'][] = 'Upload functionality affected';
                    $validation['confidence'] -= 20;
                }
            }

        } catch (Exception $e) {
            $validation['issues_found'][] = 'Validation error: ' . $e->getMessage();
            $validation['confidence'] = 0;
        }

        // Determine overall validation status
        $validation['is_valid'] = empty($validation['issues_found']) && $validation['confidence'] >= 70;

        return $validation;
    }

    /**
     * Rollback the applied fix.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @param    array    $rollback_data    Data needed for rollback.
     * @return   array                      Rollback result.
     */
    public function rollback_fix($vulnerability, $rollback_data) {
        $result = array(
            'success' => false,
            'actions_taken' => array(),
            'error_message' => ''
        );

        try {
            if (isset($rollback_data['permissions_backup'])) {
                $restored = 0;
                $total = count($rollback_data['permissions_backup']);

                foreach ($rollback_data['permissions_backup'] as $path => $original_permissions) {
                    if ($this->filesystem->exists($path)) {
                        if ($this->filesystem->chmod($path, $original_permissions)) {
                            $restored++;
                        }
                    }
                }

                if ($restored === $total) {
                    $result['success'] = true;
                    $result['actions_taken'][] = "Restored permissions for {$restored} files/directories";
                } else {
                    throw new Exception("Only restored {$restored} of {$total} permissions");
                }
            } else {
                throw new Exception('No permissions backup data available for rollback');
            }

        } catch (Exception $e) {
            $result['error_message'] = $e->getMessage();
        }

        return $result;
    }

    /**
     * Fix file permissions.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Fix result.
     */
    private function fix_file_permissions($vulnerability) {
        $result = array(
            'success' => false,
            'actions_taken' => array(),
            'changes_made' => array(),
            'error_message' => ''
        );

        try {
            $files_fixed = 0;
            $affected_files = isset($vulnerability['affected_files']) ? 
                             $vulnerability['affected_files'] : 
                             $this->scan_for_permission_issues();

            foreach ($affected_files as $file_path) {
                if (!$this->filesystem->exists($file_path)) {
                    continue;
                }

                $current_permissions = $this->get_file_permissions($file_path);
                $recommended_permissions = $this->get_recommended_file_permissions($file_path);

                if ($current_permissions !== $recommended_permissions) {
                    if ($this->filesystem->chmod($file_path, $recommended_permissions)) {
                        $files_fixed++;
                        $result['changes_made'][] = sprintf(
                            'Changed %s permissions from %o to %o',
                            $file_path,
                            $current_permissions,
                            $recommended_permissions
                        );
                    }
                }
            }

            if ($files_fixed > 0) {
                $result['success'] = true;
                $result['actions_taken'][] = "Fixed permissions for {$files_fixed} files";
            } else {
                $result['success'] = true;
                $result['actions_taken'][] = 'No file permission changes needed';
            }

        } catch (Exception $e) {
            $result['error_message'] = $e->getMessage();
        }

        return $result;
    }

    /**
     * Fix directory permissions.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Fix result.
     */
    private function fix_directory_permissions($vulnerability) {
        $result = array(
            'success' => false,
            'actions_taken' => array(),
            'changes_made' => array(),
            'error_message' => ''
        );

        try {
            $directories_fixed = 0;
            $affected_directories = isset($vulnerability['affected_files']) ? 
                                   $vulnerability['affected_files'] : 
                                   $this->scan_for_directory_permission_issues();

            foreach ($affected_directories as $dir_path) {
                if (!$this->filesystem->exists($dir_path) || !$this->filesystem->is_dir($dir_path)) {
                    continue;
                }

                $current_permissions = $this->get_file_permissions($dir_path);
                $recommended_permissions = $this->get_recommended_directory_permissions($dir_path);

                if ($current_permissions !== $recommended_permissions) {
                    if ($this->filesystem->chmod($dir_path, $recommended_permissions)) {
                        $directories_fixed++;
                        $result['changes_made'][] = sprintf(
                            'Changed %s permissions from %o to %o',
                            $dir_path,
                            $current_permissions,
                            $recommended_permissions
                        );
                    }
                }
            }

            if ($directories_fixed > 0) {
                $result['success'] = true;
                $result['actions_taken'][] = "Fixed permissions for {$directories_fixed} directories";
            } else {
                $result['success'] = true;
                $result['actions_taken'][] = 'No directory permission changes needed';
            }

        } catch (Exception $e) {
            $result['error_message'] = $e->getMessage();
        }

        return $result;
    }

    /**
     * Fix upload directory permissions.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Fix result.
     */
    private function fix_upload_permissions($vulnerability) {
        $result = array(
            'success' => false,
            'actions_taken' => array(),
            'changes_made' => array(),
            'error_message' => ''
        );

        try {
            $upload_dir = wp_upload_dir();
            $upload_path = $upload_dir['basedir'];

            if (!$this->filesystem->exists($upload_path)) {
                throw new Exception('Upload directory does not exist');
            }

            // Fix main upload directory
            $current_perms = $this->get_file_permissions($upload_path);
            if ($current_perms !== $this->recommended_permissions['uploads']) {
                if ($this->filesystem->chmod($upload_path, $this->recommended_permissions['uploads'])) {
                    $result['changes_made'][] = sprintf(
                        'Fixed upload directory permissions: %s (%o to %o)',
                        $upload_path,
                        $current_perms,
                        $this->recommended_permissions['uploads']
                    );
                }
            }

            // Fix subdirectories and files recursively
            $fixed_items = $this->fix_upload_directory_recursive($upload_path);
            $result['changes_made'] = array_merge($result['changes_made'], $fixed_items);

            // Create .htaccess for upload security
            $htaccess_result = $this->create_upload_htaccess($upload_path);
            if ($htaccess_result['created']) {
                $result['changes_made'][] = 'Created security .htaccess in upload directory';
            }

            $result['success'] = true;
            $result['actions_taken'][] = 'Fixed upload directory permissions and security';

        } catch (Exception $e) {
            $result['error_message'] = $e->getMessage();
        }

        return $result;
    }

    /**
     * Create permissions backup.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Permissions backup.
     */
    private function create_permissions_backup($vulnerability) {
        $backup = array(
            'permissions_backup' => array(),
            'timestamp' => current_time('mysql')
        );

        $affected_files = isset($vulnerability['affected_files']) ? 
                         $vulnerability['affected_files'] : 
                         $this->get_all_affected_files($vulnerability);

        foreach ($affected_files as $file_path) {
            if ($this->filesystem->exists($file_path)) {
                $backup['permissions_backup'][$file_path] = $this->get_file_permissions($file_path);
            }
        }

        return $backup;
    }

    /**
     * Get file permissions in octal format.
     *
     * @since    1.0.0
     * @param    string   $file_path   File path.
     * @return   int                   Permissions in octal.
     */
    private function get_file_permissions($file_path) {
        $perms = fileperms($file_path);
        return $perms & 0777; // Extract permission bits
    }

    /**
     * Get recommended file permissions.
     *
     * @since    1.0.0
     * @param    string   $file_path   File path.
     * @return   int                   Recommended permissions.
     */
    private function get_recommended_file_permissions($file_path) {
        $filename = basename($file_path);

        // Special cases
        if ($filename === 'wp-config.php') {
            return $this->recommended_permissions['wp_config'];
        }

        if ($filename === '.htaccess') {
            return $this->recommended_permissions['htaccess'];
        }

        // Default file permission
        return $this->recommended_permissions['files'];
    }

    /**
     * Get recommended directory permissions.
     *
     * @since    1.0.0
     * @param    string   $dir_path    Directory path.
     * @return   int                   Recommended permissions.
     */
    private function get_recommended_directory_permissions($dir_path) {
        $upload_dir = wp_upload_dir();
        
        // Upload directory
        if (strpos($dir_path, $upload_dir['basedir']) === 0) {
            return $this->recommended_permissions['uploads'];
        }

        // Default directory permission
        return $this->recommended_permissions['directories'];
    }

    /**
     * Scan for files with permission issues.
     *
     * @since    1.0.0
     * @return   array    Files with permission issues.
     */
    private function scan_for_permission_issues() {
        $problematic_files = array();

        // Check critical WordPress files
        $critical_files = array(
            ABSPATH . 'wp-config.php',
            ABSPATH . '.htaccess',
            ABSPATH . 'wp-admin/index.php',
            ABSPATH . 'wp-includes/functions.php'
        );

        foreach ($critical_files as $file) {
            if ($this->filesystem->exists($file)) {
                $perms = $this->get_file_permissions($file);
                if (in_array($perms, $this->dangerous_permissions) || 
                    $perms !== $this->get_recommended_file_permissions($file)) {
                    $problematic_files[] = $file;
                }
            }
        }

        return $problematic_files;
    }

    /**
     * Scan for directories with permission issues.
     *
     * @since    1.0.0
     * @return   array    Directories with permission issues.
     */
    private function scan_for_directory_permission_issues() {
        $problematic_dirs = array();

        // Check critical WordPress directories
        $critical_dirs = array(
            ABSPATH . 'wp-admin',
            ABSPATH . 'wp-includes',
            ABSPATH . 'wp-content',
            ABSPATH . 'wp-content/themes',
            ABSPATH . 'wp-content/plugins'
        );

        foreach ($critical_dirs as $dir) {
            if ($this->filesystem->exists($dir) && $this->filesystem->is_dir($dir)) {
                $perms = $this->get_file_permissions($dir);
                if ($perms === 0777 || $perms !== $this->recommended_permissions['directories']) {
                    $problematic_dirs[] = $dir;
                }
            }
        }

        return $problematic_dirs;
    }

    /**
     * Fix upload directory permissions recursively.
     *
     * @since    1.0.0
     * @param    string   $upload_path   Upload directory path.
     * @return   array                   Changes made.
     */
    private function fix_upload_directory_recursive($upload_path) {
        $changes = array();
        
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($upload_path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $item) {
            $item_path = $item->getPathname();
            $current_perms = $this->get_file_permissions($item_path);
            
            if ($item->isDir()) {
                if ($current_perms !== $this->recommended_permissions['uploads']) {
                    if ($this->filesystem->chmod($item_path, $this->recommended_permissions['uploads'])) {
                        $changes[] = "Fixed directory: {$item_path}";
                    }
                }
            } else {
                if ($current_perms !== $this->recommended_permissions['files']) {
                    if ($this->filesystem->chmod($item_path, $this->recommended_permissions['files'])) {
                        $changes[] = "Fixed file: {$item_path}";
                    }
                }
            }

            // Limit processing to prevent timeout
            if (count($changes) > 100) {
                $changes[] = 'Processing stopped at 100 items to prevent timeout';
                break;
            }
        }

        return $changes;
    }

    /**
     * Create .htaccess for upload directory security.
     *
     * @since    1.0.0
     * @param    string   $upload_path   Upload directory path.
     * @return   array                   Creation result.
     */
    private function create_upload_htaccess($upload_path) {
        $htaccess_path = $upload_path . '/.htaccess';
        $result = array('created' => false);

        // Don't overwrite existing .htaccess
        if ($this->filesystem->exists($htaccess_path)) {
            return $result;
        }

        $htaccess_content = '# WP-Breach Upload Directory Security
# Disable PHP execution
<Files *.php>
    Order allow,deny
    Deny from all
</Files>

# Disable script execution
AddHandler cgi-script .php .phtml .php3 .php4 .php5 .php6
Options -ExecCGI

# Block access to sensitive files
<FilesMatch "\.(htaccess|htpasswd|ini|log|sh|sql|conf)$">
    Order allow,deny
    Deny from all
</FilesMatch>';

        if ($this->filesystem->put_contents($htaccess_path, $htaccess_content)) {
            $result['created'] = true;
        }

        return $result;
    }

    /**
     * Test site functionality after permission changes.
     *
     * @since    1.0.0
     * @return   array    Functionality test result.
     */
    private function test_site_functionality() {
        $test = array(
            'passed' => true,
            'issues' => array()
        );

        // Test admin access
        if (!current_user_can('manage_options')) {
            $test['passed'] = false;
            $test['issues'][] = 'Admin capabilities affected';
        }

        // Test if WordPress can write to necessary directories
        if (!wp_is_writable(ABSPATH . 'wp-content')) {
            $test['passed'] = false;
            $test['issues'][] = 'wp-content directory not writable';
        }

        // Test upload directory
        $upload_dir = wp_upload_dir();
        if (!wp_is_writable($upload_dir['basedir'])) {
            $test['passed'] = false;
            $test['issues'][] = 'Upload directory not writable';
        }

        // Test if site loads
        $response = wp_remote_get(home_url());
        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            $test['passed'] = false;
            $test['issues'][] = 'Site not loading properly';
        }

        return $test;
    }

    /**
     * Test upload functionality.
     *
     * @since    1.0.0
     * @return   array    Upload test result.
     */
    private function test_upload_functionality() {
        $test = array(
            'passed' => true,
            'issues' => array()
        );

        // Test upload directory writability
        $upload_dir = wp_upload_dir();
        if ($upload_dir['error']) {
            $test['passed'] = false;
            $test['issues'][] = 'Upload directory error: ' . $upload_dir['error'];
            return $test;
        }

        // Test if we can create a test file
        $test_file = $upload_dir['basedir'] . '/wp-breach-test.txt';
        if (!$this->filesystem->put_contents($test_file, 'test')) {
            $test['passed'] = false;
            $test['issues'][] = 'Cannot create files in upload directory';
        } else {
            // Clean up test file
            $this->filesystem->delete($test_file);
        }

        return $test;
    }

    /**
     * Check if we can change permissions.
     *
     * @since    1.0.0
     * @return   bool    True if can change permissions.
     */
    private function can_change_permissions() {
        // Test by trying to get permissions of a known file
        try {
            $test_file = ABSPATH . 'index.php';
            if ($this->filesystem->exists($test_file)) {
                $perms = $this->get_file_permissions($test_file);
                return is_numeric($perms);
            }
        } catch (Exception $e) {
            return false;
        }

        return false;
    }

    /**
     * Identify critical files from affected files list.
     *
     * @since    1.0.0
     * @param    array    $files   List of files.
     * @return   array             Critical files.
     */
    private function identify_critical_files($files) {
        $critical_files = array();
        $critical_patterns = array('wp-config.php', '.htaccess', 'wp-admin', 'wp-includes');

        foreach ($files as $file) {
            foreach ($critical_patterns as $pattern) {
                if (strpos($file, $pattern) !== false) {
                    $critical_files[] = basename($file);
                    break;
                }
            }
        }

        return array_unique($critical_files);
    }

    /**
     * Check if this is a safe environment for permission changes.
     *
     * @since    1.0.0
     * @return   bool    True if safe environment.
     */
    private function is_safe_environment() {
        // Check if we're on a managed hosting platform that handles permissions
        $managed_hosts = array('wordpress.com', 'wpengine', 'kinsta');
        $site_url = get_site_url();

        foreach ($managed_hosts as $host) {
            if (strpos($site_url, $host) !== false) {
                return false; // Managed hosts handle permissions
            }
        }

        return true;
    }

    /**
     * Check if this is a development environment.
     *
     * @since    1.0.0
     * @return   bool    True if development environment.
     */
    private function is_development_environment() {
        $dev_indicators = array('localhost', '127.0.0.1', '.local', '.dev', '.test', 'staging');
        $site_url = get_site_url();

        foreach ($dev_indicators as $indicator) {
            if (strpos($site_url, $indicator) !== false) {
                return true;
            }
        }

        return defined('WP_DEBUG') && WP_DEBUG;
    }

    /**
     * Check if we can access affected files.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   bool                       True if can access files.
     */
    private function can_access_affected_files($vulnerability) {
        if (!isset($vulnerability['affected_files'])) {
            return true; // No specific files to check
        }

        foreach ($vulnerability['affected_files'] as $file) {
            if (!$this->filesystem->exists($file)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get all affected files for the vulnerability.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Affected files.
     */
    private function get_all_affected_files($vulnerability) {
        if (isset($vulnerability['affected_files'])) {
            return $vulnerability['affected_files'];
        }

        // Default scan for permission issues
        return array_merge(
            $this->scan_for_permission_issues(),
            $this->scan_for_directory_permission_issues()
        );
    }

    /**
     * Check if uploads directory was affected.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   bool                       True if uploads affected.
     */
    private function was_uploads_affected($vulnerability) {
        if ($vulnerability['type'] === 'upload_permissions') {
            return true;
        }

        if (isset($vulnerability['affected_files'])) {
            $upload_dir = wp_upload_dir();
            foreach ($vulnerability['affected_files'] as $file) {
                if (strpos($file, $upload_dir['basedir']) === 0) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Fix generic permission issues.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @return   array                      Fix result.
     */
    private function fix_generic_permissions($vulnerability) {
        // Combine file and directory permission fixes
        $file_result = $this->fix_file_permissions($vulnerability);
        $dir_result = $this->fix_directory_permissions($vulnerability);

        return array(
            'success' => $file_result['success'] && $dir_result['success'],
            'actions_taken' => array_merge($file_result['actions_taken'], $dir_result['actions_taken']),
            'changes_made' => array_merge($file_result['changes_made'], $dir_result['changes_made']),
            'error_message' => $file_result['error_message'] . ' ' . $dir_result['error_message']
        );
    }

    /**
     * Validate file permissions fix.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @param    array    $fix_result       Fix result.
     * @return   array                      Validation result.
     */
    private function validate_file_permissions($vulnerability, $fix_result) {
        $validation = array(
            'is_valid' => false,
            'confidence' => 85,
            'validation_tests' => array(),
            'issues_found' => array()
        );

        $affected_files = isset($vulnerability['affected_files']) ? 
                         $vulnerability['affected_files'] : 
                         $this->scan_for_permission_issues();

        $correct_permissions = 0;
        $total_files = count($affected_files);

        foreach ($affected_files as $file) {
            if ($this->filesystem->exists($file)) {
                $current_perms = $this->get_file_permissions($file);
                $recommended_perms = $this->get_recommended_file_permissions($file);

                if ($current_perms === $recommended_perms) {
                    $correct_permissions++;
                } else {
                    $validation['issues_found'][] = "File {$file} still has incorrect permissions";
                }
            }
        }

        if ($total_files > 0 && $correct_permissions === $total_files) {
            $validation['validation_tests']['file_permissions'] = array(
                'passed' => true,
                'message' => "All {$total_files} files have correct permissions"
            );
        } else {
            $validation['confidence'] -= 30;
        }

        $validation['is_valid'] = empty($validation['issues_found']);
        return $validation;
    }

    /**
     * Validate directory permissions fix.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @param    array    $fix_result       Fix result.
     * @return   array                      Validation result.
     */
    private function validate_directory_permissions($vulnerability, $fix_result) {
        $validation = array(
            'is_valid' => false,
            'confidence' => 85,
            'validation_tests' => array(),
            'issues_found' => array()
        );

        $affected_dirs = isset($vulnerability['affected_files']) ? 
                        $vulnerability['affected_files'] : 
                        $this->scan_for_directory_permission_issues();

        $correct_permissions = 0;
        $total_dirs = count($affected_dirs);

        foreach ($affected_dirs as $dir) {
            if ($this->filesystem->exists($dir) && $this->filesystem->is_dir($dir)) {
                $current_perms = $this->get_file_permissions($dir);
                $recommended_perms = $this->get_recommended_directory_permissions($dir);

                if ($current_perms === $recommended_perms) {
                    $correct_permissions++;
                } else {
                    $validation['issues_found'][] = "Directory {$dir} still has incorrect permissions";
                }
            }
        }

        if ($total_dirs > 0 && $correct_permissions === $total_dirs) {
            $validation['validation_tests']['directory_permissions'] = array(
                'passed' => true,
                'message' => "All {$total_dirs} directories have correct permissions"
            );
        } else {
            $validation['confidence'] -= 30;
        }

        $validation['is_valid'] = empty($validation['issues_found']);
        return $validation;
    }

    /**
     * Validate upload permissions fix.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @param    array    $fix_result       Fix result.
     * @return   array                      Validation result.
     */
    private function validate_upload_permissions($vulnerability, $fix_result) {
        $validation = array(
            'is_valid' => false,
            'confidence' => 80,
            'validation_tests' => array(),
            'issues_found' => array()
        );

        $upload_dir = wp_upload_dir();
        if ($upload_dir['error']) {
            $validation['issues_found'][] = 'Upload directory has errors: ' . $upload_dir['error'];
            $validation['confidence'] = 0;
            return $validation;
        }

        // Check main upload directory permissions
        $upload_perms = $this->get_file_permissions($upload_dir['basedir']);
        if ($upload_perms === $this->recommended_permissions['uploads']) {
            $validation['validation_tests']['upload_directory_permissions'] = array(
                'passed' => true,
                'message' => 'Upload directory has correct permissions'
            );
        } else {
            $validation['issues_found'][] = 'Upload directory permissions still incorrect';
            $validation['confidence'] -= 20;
        }

        // Check if .htaccess exists for security
        $htaccess_path = $upload_dir['basedir'] . '/.htaccess';
        if ($this->filesystem->exists($htaccess_path)) {
            $validation['validation_tests']['upload_security'] = array(
                'passed' => true,
                'message' => 'Upload directory security .htaccess exists'
            );
        }

        $validation['is_valid'] = empty($validation['issues_found']);
        return $validation;
    }

    /**
     * Validate generic permissions fix.
     *
     * @since    1.0.0
     * @param    array    $vulnerability    Vulnerability details.
     * @param    array    $fix_result       Fix result.
     * @return   array                      Validation result.
     */
    private function validate_generic_permissions($vulnerability, $fix_result) {
        $file_validation = $this->validate_file_permissions($vulnerability, $fix_result);
        $dir_validation = $this->validate_directory_permissions($vulnerability, $fix_result);

        return array(
            'is_valid' => $file_validation['is_valid'] && $dir_validation['is_valid'],
            'confidence' => min($file_validation['confidence'], $dir_validation['confidence']),
            'validation_tests' => array_merge(
                $file_validation['validation_tests'],
                $dir_validation['validation_tests']
            ),
            'issues_found' => array_merge(
                $file_validation['issues_found'],
                $dir_validation['issues_found']
            )
        );
    }
}
