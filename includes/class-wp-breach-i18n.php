<?php
/**
 * Define the internationalization functionality
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 */

/**
 * Define the internationalization functionality.
 *
 * Loads and defines the internationalization files for this plugin
 * so that it is ready for translation.
 *
 * @since      1.0.0
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_i18n {

	/**
	 * Load the plugin text domain for translation.
	 *
	 * @since    1.0.0
	 */
	public function load_plugin_textdomain() {
		load_plugin_textdomain(
			'wp-breach',
			false,
			dirname( dirname( plugin_basename( __FILE__ ) ) ) . '/languages/'
		);
	}

	/**
	 * Get available languages for the plugin
	 *
	 * @since    1.0.0
	 * @return   array Array of available language codes and names
	 */
	public function get_available_languages() {
		$languages = array(
			'en_US' => __( 'English (United States)', 'wp-breach' ),
			'zh_CN' => __( 'Chinese (Simplified)', 'wp-breach' ),
			'zh_TW' => __( 'Chinese (Traditional)', 'wp-breach' ),
			'es_ES' => __( 'Spanish (Spain)', 'wp-breach' ),
			'fr_FR' => __( 'French (France)', 'wp-breach' ),
			'de_DE' => __( 'German (Germany)', 'wp-breach' ),
			'ja'    => __( 'Japanese', 'wp-breach' ),
			'ko_KR' => __( 'Korean', 'wp-breach' ),
			'ru_RU' => __( 'Russian', 'wp-breach' ),
			'pt_BR' => __( 'Portuguese (Brazil)', 'wp-breach' ),
			'it_IT' => __( 'Italian', 'wp-breach' ),
			'ar'    => __( 'Arabic', 'wp-breach' ),
		);

		return apply_filters( 'wp_breach_available_languages', $languages );
	}

	/**
	 * Get the current language code
	 *
	 * @since    1.0.0
	 * @return   string Current language code
	 */
	public function get_current_language() {
		return get_locale();
	}

	/**
	 * Check if a specific language is available
	 *
	 * @since    1.0.0
	 * @param    string $language_code The language code to check
	 * @return   bool   True if language is available, false otherwise
	 */
	public function is_language_available( $language_code ) {
		$available_languages = $this->get_available_languages();
		return array_key_exists( $language_code, $available_languages );
	}

	/**
	 * Get RTL (Right-to-Left) languages
	 *
	 * @since    1.0.0
	 * @return   array Array of RTL language codes
	 */
	public function get_rtl_languages() {
		$rtl_languages = array(
			'ar',      // Arabic
			'he_IL',   // Hebrew
			'fa_IR',   // Persian/Farsi
			'ur',      // Urdu
			'ps',      // Pashto
			'sd_PK',   // Sindhi
			'ug_CN',   // Uyghur
		);

		return apply_filters( 'wp_breach_rtl_languages', $rtl_languages );
	}

	/**
	 * Check if current language is RTL
	 *
	 * @since    1.0.0
	 * @return   bool True if current language is RTL, false otherwise
	 */
	public function is_rtl() {
		return in_array( $this->get_current_language(), $this->get_rtl_languages() ) || is_rtl();
	}

	/**
	 * Get language direction class for CSS
	 *
	 * @since    1.0.0
	 * @return   string 'rtl' or 'ltr'
	 */
	public function get_language_direction() {
		return $this->is_rtl() ? 'rtl' : 'ltr';
	}

	/**
	 * Format date according to current locale
	 *
	 * @since    1.0.0
	 * @param    string $date     Date string or timestamp
	 * @param    string $format   Optional. Date format. Default is WordPress date format.
	 * @return   string Formatted date string
	 */
	public function format_date( $date, $format = '' ) {
		if ( empty( $format ) ) {
			$format = get_option( 'date_format' );
		}

		if ( is_numeric( $date ) ) {
			return date_i18n( $format, $date );
		} else {
			return date_i18n( $format, strtotime( $date ) );
		}
	}

	/**
	 * Format time according to current locale
	 *
	 * @since    1.0.0
	 * @param    string $time     Time string or timestamp
	 * @param    string $format   Optional. Time format. Default is WordPress time format.
	 * @return   string Formatted time string
	 */
	public function format_time( $time, $format = '' ) {
		if ( empty( $format ) ) {
			$format = get_option( 'time_format' );
		}

		if ( is_numeric( $time ) ) {
			return date_i18n( $format, $time );
		} else {
			return date_i18n( $format, strtotime( $time ) );
		}
	}

	/**
	 * Format datetime according to current locale
	 *
	 * @since    1.0.0
	 * @param    string $datetime  DateTime string or timestamp
	 * @param    string $format    Optional. DateTime format. Default combines WordPress date and time formats.
	 * @return   string Formatted datetime string
	 */
	public function format_datetime( $datetime, $format = '' ) {
		if ( empty( $format ) ) {
			$format = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
		}

		if ( is_numeric( $datetime ) ) {
			return date_i18n( $format, $datetime );
		} else {
			return date_i18n( $format, strtotime( $datetime ) );
		}
	}

	/**
	 * Format number according to current locale
	 *
	 * @since    1.0.0
	 * @param    float $number    Number to format
	 * @param    int   $decimals  Optional. Number of decimal places. Default is 2.
	 * @return   string Formatted number string
	 */
	public function format_number( $number, $decimals = 2 ) {
		return number_format_i18n( $number, $decimals );
	}

	/**
	 * Get translated string with fallback
	 *
	 * @since    1.0.0
	 * @param    string $string   String to translate
	 * @param    string $fallback Fallback string if translation not found
	 * @param    string $domain   Optional. Text domain. Default is 'wp-breach'.
	 * @return   string Translated string or fallback
	 */
	public function get_string( $string, $fallback = '', $domain = 'wp-breach' ) {
		$translated = __( $string, $domain );

		// If translation is the same as original and fallback is provided
		if ( $translated === $string && ! empty( $fallback ) ) {
			return $fallback;
		}

		return $translated;
	}

	/**
	 * Get plural string translation
	 *
	 * @since    1.0.0
	 * @param    string $singular Singular form
	 * @param    string $plural   Plural form
	 * @param    int    $number   Number to determine which form to use
	 * @param    string $domain   Optional. Text domain. Default is 'wp-breach'.
	 * @return   string Translated string
	 */
	public function get_plural( $singular, $plural, $number, $domain = 'wp-breach' ) {
		return _n( $singular, $plural, $number, $domain );
	}

	/**
	 * Get language file path for a specific language
	 *
	 * @since    1.0.0
	 * @param    string $language_code Language code
	 * @return   string|false Language file path or false if not found
	 */
	public function get_language_file_path( $language_code ) {
		$languages_dir = dirname( dirname( plugin_basename( __FILE__ ) ) ) . '/languages/';
		$mo_file = $languages_dir . 'wp-breach-' . $language_code . '.mo';
		$po_file = $languages_dir . 'wp-breach-' . $language_code . '.po';

		if ( file_exists( WP_PLUGIN_DIR . '/' . $mo_file ) ) {
			return WP_PLUGIN_DIR . '/' . $mo_file;
		} elseif ( file_exists( WP_PLUGIN_DIR . '/' . $po_file ) ) {
			return WP_PLUGIN_DIR . '/' . $po_file;
		}

		return false;
	}

	/**
	 * Generate language statistics
	 *
	 * @since    1.0.0
	 * @return   array Language usage statistics
	 */
	public function get_language_stats() {
		$stats = array(
			'current_language' => $this->get_current_language(),
			'is_rtl'          => $this->is_rtl(),
			'available_count' => count( $this->get_available_languages() ),
			'textdomain'      => 'wp-breach',
		);

		return $stats;
	}
}
