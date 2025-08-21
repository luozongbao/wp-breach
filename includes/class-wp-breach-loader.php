<?php
/**
 * Register all actions and filters for the plugin
 *
 * @link       https://github.com/luozongbao
 * @since      1.0.0
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 */

/**
 * Register all actions and filters for the plugin.
 *
 * Maintain a list of all hooks that are registered throughout
 * the plugin, and register them with the WordPress API. Call the
 * run function to execute the list of actions and filters.
 *
 * @package    WP_Breach
 * @subpackage WP_Breach/includes
 * @author     luozongbao <luo.zongbao@outlook.com>
 */
class WP_Breach_Loader {

	/**
	 * The array of actions registered with WordPress.
	 *
	 * @since    1.0.0
	 * @access   protected
	 * @var      array    $actions    The actions registered with WordPress to fire when the plugin loads.
	 */
	protected $actions;

	/**
	 * The array of filters registered with WordPress.
	 *
	 * @since    1.0.0
	 * @access   protected
	 * @var      array    $filters    The filters registered with WordPress to fire when the plugin loads.
	 */
	protected $filters;

	/**
	 * The array of shortcodes registered with WordPress.
	 *
	 * @since    1.0.0
	 * @access   protected
	 * @var      array    $shortcodes    The shortcodes registered with WordPress to fire when the plugin loads.
	 */
	protected $shortcodes;

	/**
	 * Initialize the collections used to maintain the actions and filters.
	 *
	 * @since    1.0.0
	 */
	public function __construct() {
		$this->actions = array();
		$this->filters = array();
		$this->shortcodes = array();
	}

	/**
	 * Add a new action to the collection to be registered with WordPress.
	 *
	 * @since    1.0.0
	 * @param    string               $hook             The name of the WordPress action that is being registered.
	 * @param    object               $component        A reference to the instance of the object on which the action is defined.
	 * @param    string               $callback         The name of the function definition on the $component.
	 * @param    int                  $priority         Optional. The priority at which the function should be fired. Default is 10.
	 * @param    int                  $accepted_args    Optional. The number of arguments that should be passed to the $callback. Default is 1.
	 */
	public function add_action( $hook, $component, $callback, $priority = 10, $accepted_args = 1 ) {
		$this->actions = $this->add( $this->actions, $hook, $component, $callback, $priority, $accepted_args );
	}

	/**
	 * Add a new filter to the collection to be registered with WordPress.
	 *
	 * @since    1.0.0
	 * @param    string               $hook             The name of the WordPress filter that is being registered.
	 * @param    object               $component        A reference to the instance of the object on which the filter is defined.
	 * @param    string               $callback         The name of the function definition on the $component.
	 * @param    int                  $priority         Optional. The priority at which the function should be fired. Default is 10.
	 * @param    int                  $accepted_args    Optional. The number of arguments that should be passed to the $callback. Default is 1.
	 */
	public function add_filter( $hook, $component, $callback, $priority = 10, $accepted_args = 1 ) {
		$this->filters = $this->add( $this->filters, $hook, $component, $callback, $priority, $accepted_args );
	}

	/**
	 * Add a new shortcode to the collection to be registered with WordPress
	 *
	 * @since    1.0.0
	 * @param    string               $tag              The name of the new shortcode.
	 * @param    object               $component        A reference to the instance of the object on which the shortcode is defined.
	 * @param    string               $callback         The name of the function that defines the shortcode.
	 */
	public function add_shortcode( $tag, $component, $callback ) {
		$this->shortcodes = $this->add( $this->shortcodes, $tag, $component, $callback, '', '' );
	}

	/**
	 * A utility function that is used to register the actions and hooks into a single
	 * collection.
	 *
	 * @since    1.0.0
	 * @access   private
	 * @param    array                $hooks            The collection of hooks that is being registered (that is, actions or filters).
	 * @param    string               $hook             The name of the WordPress filter that is being registered.
	 * @param    object               $component        A reference to the instance of the object on which the filter is defined.
	 * @param    string               $callback         The name of the function definition on the $component.
	 * @param    int                  $priority         The priority at which the function should be fired.
	 * @param    int                  $accepted_args    The number of arguments that should be passed to the $callback.
	 * @return   array                                  The collection of actions and filters registered with WordPress.
	 */
	private function add( $hooks, $hook, $component, $callback, $priority, $accepted_args ) {
		$hooks[] = array(
			'hook'          => $hook,
			'component'     => $component,
			'callback'      => $callback,
			'priority'      => $priority,
			'accepted_args' => $accepted_args,
		);

		return $hooks;
	}

	/**
	 * Register the filters and actions with WordPress.
	 *
	 * @since    1.0.0
	 */
	public function run() {
		// Register all actions
		foreach ( $this->actions as $hook ) {
			add_action( $hook['hook'], array( $hook['component'], $hook['callback'] ), $hook['priority'], $hook['accepted_args'] );
		}

		// Register all filters
		foreach ( $this->filters as $hook ) {
			add_filter( $hook['hook'], array( $hook['component'], $hook['callback'] ), $hook['priority'], $hook['accepted_args'] );
		}

		// Register all shortcodes
		foreach ( $this->shortcodes as $hook ) {
			add_shortcode( $hook['hook'], array( $hook['component'], $hook['callback'] ) );
		}
	}

	/**
	 * Get all registered actions
	 *
	 * @since    1.0.0
	 * @return   array    The actions registered with the loader.
	 */
	public function get_actions() {
		return $this->actions;
	}

	/**
	 * Get all registered filters
	 *
	 * @since    1.0.0
	 * @return   array    The filters registered with the loader.
	 */
	public function get_filters() {
		return $this->filters;
	}

	/**
	 * Get all registered shortcodes
	 *
	 * @since    1.0.0
	 * @return   array    The shortcodes registered with the loader.
	 */
	public function get_shortcodes() {
		return $this->shortcodes;
	}

	/**
	 * Remove a specific action from the collection
	 *
	 * @since    1.0.0
	 * @param    string $hook The name of the WordPress action to remove.
	 * @param    string $callback The callback function to remove.
	 * @return   bool   True if the action was removed, false otherwise.
	 */
	public function remove_action( $hook, $callback ) {
		foreach ( $this->actions as $key => $action ) {
			if ( $action['hook'] === $hook && $action['callback'] === $callback ) {
				unset( $this->actions[ $key ] );
				return true;
			}
		}
		return false;
	}

	/**
	 * Remove a specific filter from the collection
	 *
	 * @since    1.0.0
	 * @param    string $hook The name of the WordPress filter to remove.
	 * @param    string $callback The callback function to remove.
	 * @return   bool   True if the filter was removed, false otherwise.
	 */
	public function remove_filter( $hook, $callback ) {
		foreach ( $this->filters as $key => $filter ) {
			if ( $filter['hook'] === $hook && $filter['callback'] === $callback ) {
				unset( $this->filters[ $key ] );
				return true;
			}
		}
		return false;
	}

	/**
	 * Remove a specific shortcode from the collection
	 *
	 * @since    1.0.0
	 * @param    string $tag The shortcode tag to remove.
	 * @return   bool   True if the shortcode was removed, false otherwise.
	 */
	public function remove_shortcode( $tag ) {
		foreach ( $this->shortcodes as $key => $shortcode ) {
			if ( $shortcode['hook'] === $tag ) {
				unset( $this->shortcodes[ $key ] );
				return true;
			}
		}
		return false;
	}

	/**
	 * Check if a specific action is registered
	 *
	 * @since    1.0.0
	 * @param    string $hook The name of the WordPress action.
	 * @param    string $callback The callback function to check.
	 * @return   bool   True if the action is registered, false otherwise.
	 */
	public function has_action( $hook, $callback ) {
		foreach ( $this->actions as $action ) {
			if ( $action['hook'] === $hook && $action['callback'] === $callback ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check if a specific filter is registered
	 *
	 * @since    1.0.0
	 * @param    string $hook The name of the WordPress filter.
	 * @param    string $callback The callback function to check.
	 * @return   bool   True if the filter is registered, false otherwise.
	 */
	public function has_filter( $hook, $callback ) {
		foreach ( $this->filters as $filter ) {
			if ( $filter['hook'] === $hook && $filter['callback'] === $callback ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check if a specific shortcode is registered
	 *
	 * @since    1.0.0
	 * @param    string $tag The shortcode tag to check.
	 * @return   bool   True if the shortcode is registered, false otherwise.
	 */
	public function has_shortcode( $tag ) {
		foreach ( $this->shortcodes as $shortcode ) {
			if ( $shortcode['hook'] === $tag ) {
				return true;
			}
		}
		return false;
	}
}
