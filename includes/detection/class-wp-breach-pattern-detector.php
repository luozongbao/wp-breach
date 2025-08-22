<?php

/**
 * The pattern-based vulnerability detector.
 *
 * This class handles pattern-based vulnerability detection using
 * regular expressions and predefined patterns.
 *
 * @link       https://wpbreach.com
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection
 */

/**
 * The pattern detector class.
 *
 * This class provides pattern-based vulnerability detection using
 * regular expressions and signature matching.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes/detection
 * @author     WP Breach Team
 */
class WP_Breach_Pattern_Detector {

    /**
     * Loaded pattern libraries.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $patterns    Array of loaded patterns.
     */
    protected $patterns;

    /**
     * Pattern cache.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $pattern_cache    Cache for compiled patterns.
     */
    protected $pattern_cache;

    /**
     * Detection statistics.
     *
     * @since    1.0.0
     * @access   protected
     * @var      array    $stats    Detection statistics.
     */
    protected $stats;

    /**
     * Initialize the pattern detector.
     *
     * @since    1.0.0
     */
    public function __construct() {
        $this->patterns = array();
        $this->pattern_cache = array();
        $this->stats = array(
            'patterns_loaded' => 0,
            'detections_run' => 0,
            'vulnerabilities_found' => 0
        );
        $this->load_patterns();
    }

    /**
     * Load all pattern libraries.
     *
     * @since    1.0.0
     */
    private function load_patterns() {
        $pattern_files = array(
            'sql-injection' => 'sql-injection-patterns.php',
            'xss' => 'xss-patterns.php',
            'general' => 'general-patterns.php'
        );

        foreach ($pattern_files as $type => $file) {
            $file_path = plugin_dir_path(dirname(__FILE__)) . 'detection/patterns/' . $file;
            if (file_exists($file_path)) {
                $patterns = include $file_path;
                if (is_array($patterns)) {
                    $this->patterns[$type] = $patterns;
                    $this->stats['patterns_loaded'] += count($patterns);
                }
            }
        }
    }

    /**
     * Detect patterns in content.
     *
     * @since    1.0.0
     * @param    string    $content         The content to analyze.
     * @param    string    $file_path       The file path being analyzed.
     * @return   array                      Array of detected vulnerabilities.
     */
    public function detect_patterns($content, $file_path = '') {
        $this->stats['detections_run']++;
        $vulnerabilities = array();

        foreach ($this->patterns as $category => $pattern_set) {
            $category_results = $this->detect_category_patterns($content, $file_path, $category, $pattern_set);
            if (!empty($category_results)) {
                $vulnerabilities = array_merge($vulnerabilities, $category_results);
            }
        }

        $this->stats['vulnerabilities_found'] += count($vulnerabilities);
        return $vulnerabilities;
    }

    /**
     * Detect patterns for a specific category.
     *
     * @since    1.0.0
     * @param    string    $content         The content to analyze.
     * @param    string    $file_path       The file path being analyzed.
     * @param    string    $category        The pattern category.
     * @param    array     $patterns        The patterns to check.
     * @return   array                      Array of detected vulnerabilities.
     */
    private function detect_category_patterns($content, $file_path, $category, $patterns) {
        $vulnerabilities = array();
        $lines = explode("\n", $content);

        foreach ($patterns as $pattern_data) {
            $matches = $this->match_pattern($content, $pattern_data);
            
            foreach ($matches as $match) {
                $line_number = $this->get_line_number($content, $match['offset']);
                $context = $this->get_context($lines, $line_number);
                
                $vulnerability = array(
                    'type' => $category,
                    'subtype' => $pattern_data['name'],
                    'severity' => $pattern_data['severity'],
                    'confidence' => $pattern_data['confidence'],
                    'description' => $pattern_data['description'],
                    'line' => $line_number,
                    'column' => $match['column'],
                    'matched_text' => $match['text'],
                    'context' => $context,
                    'pattern_id' => $pattern_data['id'],
                    'cwe_id' => isset($pattern_data['cwe']) ? $pattern_data['cwe'] : null,
                    'owasp_category' => isset($pattern_data['owasp']) ? $pattern_data['owasp'] : null,
                    'recommendation' => isset($pattern_data['fix']) ? $pattern_data['fix'] : '',
                    'references' => isset($pattern_data['references']) ? $pattern_data['references'] : array()
                );

                $vulnerabilities[] = $vulnerability;
            }
        }

        return $vulnerabilities;
    }

    /**
     * Match a pattern against content.
     *
     * @since    1.0.0
     * @param    string    $content         The content to analyze.
     * @param    array     $pattern_data    The pattern data.
     * @return   array                      Array of matches.
     */
    private function match_pattern($content, $pattern_data) {
        $matches = array();
        $pattern = $pattern_data['pattern'];
        $flags = isset($pattern_data['flags']) ? $pattern_data['flags'] : 0;

        // Add case insensitive flag by default
        if (!($flags & PREG_PATTERN_ORDER)) {
            $flags |= PREG_OFFSET_CAPTURE;
        }

        $result = preg_match_all($pattern, $content, $pattern_matches, $flags);
        
        if ($result > 0) {
            for ($i = 0; $i < count($pattern_matches[0]); $i++) {
                $match_text = $pattern_matches[0][$i][0];
                $match_offset = $pattern_matches[0][$i][1];
                
                // Calculate column position
                $column = $this->get_column_position($content, $match_offset);
                
                $matches[] = array(
                    'text' => $match_text,
                    'offset' => $match_offset,
                    'column' => $column,
                    'length' => strlen($match_text)
                );
            }
        }

        return $matches;
    }

    /**
     * Get line number from content offset.
     *
     * @since    1.0.0
     * @param    string    $content         The content.
     * @param    int       $offset          The offset position.
     * @return   int                        The line number.
     */
    private function get_line_number($content, $offset) {
        return substr_count(substr($content, 0, $offset), "\n") + 1;
    }

    /**
     * Get column position from content offset.
     *
     * @since    1.0.0
     * @param    string    $content         The content.
     * @param    int       $offset          The offset position.
     * @return   int                        The column position.
     */
    private function get_column_position($content, $offset) {
        $line_start = strrpos(substr($content, 0, $offset), "\n");
        $line_start = ($line_start === false) ? 0 : $line_start + 1;
        return $offset - $line_start + 1;
    }

    /**
     * Get context around a line.
     *
     * @since    1.0.0
     * @param    array     $lines           Array of content lines.
     * @param    int       $line_number     The target line number.
     * @param    int       $context_lines   Number of context lines.
     * @return   array                      Context information.
     */
    private function get_context($lines, $line_number, $context_lines = 3) {
        $start = max(0, $line_number - $context_lines - 1);
        $end = min(count($lines), $line_number + $context_lines);
        
        $context_array = array();
        for ($i = $start; $i < $end; $i++) {
            $context_array[] = array(
                'line_number' => $i + 1,
                'content' => isset($lines[$i]) ? $lines[$i] : '',
                'is_target' => ($i + 1) === $line_number
            );
        }

        return array(
            'lines' => $context_array,
            'target_line' => $line_number,
            'before' => max(0, $line_number - $context_lines - 1),
            'after' => min(count($lines), $line_number + $context_lines)
        );
    }

    /**
     * Add custom pattern.
     *
     * @since    1.0.0
     * @param    string    $category        Pattern category.
     * @param    array     $pattern_data    Pattern data.
     * @return   bool                       Success status.
     */
    public function add_pattern($category, $pattern_data) {
        // Validate pattern data
        $required_fields = array('id', 'name', 'pattern', 'severity', 'confidence', 'description');
        foreach ($required_fields as $field) {
            if (!isset($pattern_data[$field])) {
                return false;
            }
        }

        // Validate regex pattern
        if (@preg_match($pattern_data['pattern'], '') === false) {
            return false;
        }

        if (!isset($this->patterns[$category])) {
            $this->patterns[$category] = array();
        }

        $this->patterns[$category][] = $pattern_data;
        $this->stats['patterns_loaded']++;

        return true;
    }

    /**
     * Remove pattern by ID.
     *
     * @since    1.0.0
     * @param    string    $pattern_id      Pattern ID to remove.
     * @return   bool                       Success status.
     */
    public function remove_pattern($pattern_id) {
        foreach ($this->patterns as $category => &$pattern_set) {
            foreach ($pattern_set as $index => $pattern_data) {
                if ($pattern_data['id'] === $pattern_id) {
                    unset($pattern_set[$index]);
                    $pattern_set = array_values($pattern_set); // Re-index
                    $this->stats['patterns_loaded']--;
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Get pattern by ID.
     *
     * @since    1.0.0
     * @param    string    $pattern_id      Pattern ID.
     * @return   array|null                 Pattern data or null if not found.
     */
    public function get_pattern($pattern_id) {
        foreach ($this->patterns as $category => $pattern_set) {
            foreach ($pattern_set as $pattern_data) {
                if ($pattern_data['id'] === $pattern_id) {
                    return array_merge($pattern_data, array('category' => $category));
                }
            }
        }
        return null;
    }

    /**
     * Get all patterns for a category.
     *
     * @since    1.0.0
     * @param    string    $category        Pattern category.
     * @return   array                      Array of patterns.
     */
    public function get_category_patterns($category) {
        return isset($this->patterns[$category]) ? $this->patterns[$category] : array();
    }

    /**
     * Get all loaded patterns.
     *
     * @since    1.0.0
     * @return   array                      All patterns.
     */
    public function get_all_patterns() {
        return $this->patterns;
    }

    /**
     * Test pattern against content.
     *
     * @since    1.0.0
     * @param    string    $pattern         Regular expression pattern.
     * @param    string    $content         Content to test against.
     * @return   array                      Test results.
     */
    public function test_pattern($pattern, $content) {
        $start_time = microtime(true);
        
        // Validate pattern
        if (@preg_match($pattern, '') === false) {
            return array(
                'success' => false,
                'error' => 'Invalid regular expression pattern',
                'matches' => array()
            );
        }

        $matches = array();
        $result = preg_match_all($pattern, $content, $pattern_matches, PREG_OFFSET_CAPTURE);
        
        if ($result > 0) {
            for ($i = 0; $i < count($pattern_matches[0]); $i++) {
                $match_text = $pattern_matches[0][$i][0];
                $match_offset = $pattern_matches[0][$i][1];
                $line_number = $this->get_line_number($content, $match_offset);
                $column = $this->get_column_position($content, $match_offset);
                
                $matches[] = array(
                    'text' => $match_text,
                    'offset' => $match_offset,
                    'line' => $line_number,
                    'column' => $column,
                    'length' => strlen($match_text)
                );
            }
        }

        $end_time = microtime(true);
        $execution_time = $end_time - $start_time;

        return array(
            'success' => true,
            'pattern' => $pattern,
            'matches' => $matches,
            'match_count' => count($matches),
            'execution_time' => $execution_time
        );
    }

    /**
     * Optimize patterns for better performance.
     *
     * @since    1.0.0
     */
    public function optimize_patterns() {
        foreach ($this->patterns as $category => &$pattern_set) {
            // Sort patterns by confidence (higher confidence first)
            usort($pattern_set, function($a, $b) {
                return $b['confidence'] <=> $a['confidence'];
            });

            // Cache compiled patterns
            foreach ($pattern_set as &$pattern_data) {
                if (!isset($this->pattern_cache[$pattern_data['id']])) {
                    $this->pattern_cache[$pattern_data['id']] = $pattern_data['pattern'];
                }
            }
        }
    }

    /**
     * Get detection statistics.
     *
     * @since    1.0.0
     * @return   array                      Detection statistics.
     */
    public function get_statistics() {
        return array_merge($this->stats, array(
            'pattern_categories' => count($this->patterns),
            'cached_patterns' => count($this->pattern_cache)
        ));
    }

    /**
     * Reset statistics.
     *
     * @since    1.0.0
     */
    public function reset_statistics() {
        $this->stats = array(
            'patterns_loaded' => count($this->patterns),
            'detections_run' => 0,
            'vulnerabilities_found' => 0
        );
    }

    /**
     * Export patterns to array.
     *
     * @since    1.0.0
     * @param    string    $category        Category to export (optional).
     * @return   array                      Exported patterns.
     */
    public function export_patterns($category = null) {
        if ($category) {
            return isset($this->patterns[$category]) ? $this->patterns[$category] : array();
        }
        return $this->patterns;
    }

    /**
     * Import patterns from array.
     *
     * @since    1.0.0
     * @param    array     $patterns        Patterns to import.
     * @param    bool      $replace         Whether to replace existing patterns.
     * @return   int                        Number of patterns imported.
     */
    public function import_patterns($patterns, $replace = false) {
        $imported = 0;

        if ($replace) {
            $this->patterns = array();
            $this->stats['patterns_loaded'] = 0;
        }

        foreach ($patterns as $category => $pattern_set) {
            if (!isset($this->patterns[$category])) {
                $this->patterns[$category] = array();
            }

            foreach ($pattern_set as $pattern_data) {
                if ($this->add_pattern($category, $pattern_data)) {
                    $imported++;
                }
            }
        }

        return $imported;
    }

    /**
     * Validate pattern structure.
     *
     * @since    1.0.0
     * @param    array     $pattern_data    Pattern data to validate.
     * @return   array                      Validation result.
     */
    public function validate_pattern($pattern_data) {
        $errors = array();
        $required_fields = array('id', 'name', 'pattern', 'severity', 'confidence', 'description');

        // Check required fields
        foreach ($required_fields as $field) {
            if (!isset($pattern_data[$field]) || empty($pattern_data[$field])) {
                $errors[] = "Missing required field: {$field}";
            }
        }

        // Validate pattern syntax
        if (isset($pattern_data['pattern'])) {
            if (@preg_match($pattern_data['pattern'], '') === false) {
                $errors[] = "Invalid regular expression pattern";
            }
        }

        // Validate severity
        if (isset($pattern_data['severity'])) {
            $valid_severities = array('critical', 'high', 'medium', 'low', 'info');
            if (!in_array(strtolower($pattern_data['severity']), $valid_severities)) {
                $errors[] = "Invalid severity level";
            }
        }

        // Validate confidence
        if (isset($pattern_data['confidence'])) {
            if (!is_numeric($pattern_data['confidence']) || 
                $pattern_data['confidence'] < 0 || 
                $pattern_data['confidence'] > 1) {
                $errors[] = "Confidence must be a number between 0 and 1";
            }
        }

        return array(
            'valid' => empty($errors),
            'errors' => $errors
        );
    }
}
