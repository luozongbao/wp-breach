<?php
/**
 * Unit tests for WP_Breach_Cache_Manager class.
 *
 * @package WP_Breach
 * @subpackage Tests
 */

class WP_Breach_Cache_Manager_Test extends WP_Breach_Test_Case {

	/**
	 * Cache manager instance
	 *
	 * @var WP_Breach_Cache_Manager
	 */
	private $cache_manager;

	/**
	 * Set up test environment
	 */
	public function setUp(): void {
		parent::setUp();
		$this->cache_manager = new WP_Breach_Cache_Manager();
	}

	/**
	 * Test cache manager initialization
	 */
	public function test_cache_manager_initialization() {
		$this->assertInstanceOf( 'WP_Breach_Cache_Manager', $this->cache_manager );
		$this->assertTrue( method_exists( $this->cache_manager, 'get_cached_data' ) );
		$this->assertTrue( method_exists( $this->cache_manager, 'set_cached_data' ) );
		$this->assertTrue( method_exists( $this->cache_manager, 'invalidate_cache' ) );
	}

	/**
	 * Test basic cache operations
	 */
	public function test_basic_cache_operations() {
		$test_key = 'test_cache_key';
		$test_data = array( 'test' => 'data', 'number' => 123 );
		$cache_group = 'test_group';
		
		// Test cache miss initially
		$cached_data = $this->cache_manager->get_cached_data( $test_key, $cache_group );
		$this->assertFalse( $cached_data );
		
		// Test cache set
		$result = $this->cache_manager->set_cached_data( $test_key, $test_data, 300, $cache_group );
		$this->assertTrue( $result );
		
		// Test cache hit
		$cached_data = $this->cache_manager->get_cached_data( $test_key, $cache_group );
		$this->assertEquals( $test_data, $cached_data );
	}

	/**
	 * Test multi-level caching strategy
	 */
	public function test_multi_level_caching() {
		$test_key = 'multi_level_test';
		$test_data = 'test data for multi-level caching';
		
		// Set data in cache
		$this->cache_manager->set_cached_data( $test_key, $test_data, 300, 'multi_level' );
		
		// Should be retrievable from object cache
		$from_object_cache = $this->cache_manager->get_cached_data( $test_key, 'multi_level' );
		$this->assertEquals( $test_data, $from_object_cache );
		
		// Clear object cache to test fallback
		wp_cache_delete( $test_key, 'multi_level' );
		
		// Should still be retrievable from transient fallback
		$from_transient = $this->cache_manager->get_cached_data( $test_key, 'multi_level' );
		$this->assertEquals( $test_data, $from_transient );
	}

	/**
	 * Test cache invalidation
	 */
	public function test_cache_invalidation() {
		$test_key = 'invalidation_test';
		$test_data = 'data to be invalidated';
		$cache_group = 'invalidation_group';
		
		// Set cache data
		$this->cache_manager->set_cached_data( $test_key, $test_data, 300, $cache_group );
		
		// Verify it's cached
		$cached_data = $this->cache_manager->get_cached_data( $test_key, $cache_group );
		$this->assertEquals( $test_data, $cached_data );
		
		// Invalidate cache
		$result = $this->cache_manager->invalidate_cache( $test_key, $cache_group );
		$this->assertTrue( $result );
		
		// Should be cache miss after invalidation
		$cached_data = $this->cache_manager->get_cached_data( $test_key, $cache_group );
		$this->assertFalse( $cached_data );
	}

	/**
	 * Test cache group operations
	 */
	public function test_cache_group_operations() {
		$group_name = 'test_group_operations';
		
		// Set multiple items in the same group
		$items = array(
			'item1' => 'data1',
			'item2' => 'data2',
			'item3' => 'data3'
		);
		
		foreach ( $items as $key => $data ) {
			$this->cache_manager->set_cached_data( $key, $data, 300, $group_name );
		}
		
		// Verify all items are cached
		foreach ( $items as $key => $expected_data ) {
			$cached_data = $this->cache_manager->get_cached_data( $key, $group_name );
			$this->assertEquals( $expected_data, $cached_data );
		}
		
		// Clear entire group
		$result = $this->cache_manager->clear_cache_group( $group_name );
		$this->assertTrue( $result );
		
		// All items should be invalidated
		foreach ( $items as $key => $data ) {
			$cached_data = $this->cache_manager->get_cached_data( $key, $group_name );
			$this->assertFalse( $cached_data );
		}
	}

	/**
	 * Test scan results caching
	 */
	public function test_scan_results_caching() {
		$scan_id = 'test_scan_123';
		$scan_results = array(
			'scan_id' => $scan_id,
			'vulnerabilities' => array(
				array(
					'type' => 'xss',
					'severity' => 'high',
					'file' => '/test/file.php'
				)
			),
			'files_scanned' => 150,
			'scan_duration' => 45.67
		);
		
		// Cache scan results
		$result = $this->cache_manager->cache_scan_results( $scan_id, $scan_results );
		$this->assertTrue( $result );
		
		// Retrieve cached scan results
		$cached_results = $this->cache_manager->get_cached_scan_results( $scan_id );
		$this->assertEquals( $scan_results, $cached_results );
		
		// Test scan results invalidation
		$this->cache_manager->invalidate_scan_cache( $scan_id );
		$cached_results = $this->cache_manager->get_cached_scan_results( $scan_id );
		$this->assertFalse( $cached_results );
	}

	/**
	 * Test file hash caching
	 */
	public function test_file_hash_caching() {
		// Create a temporary test file
		$test_files = $this->create_test_files( 1 );
		$test_file = $test_files[0];
		
		// Test file hash caching
		$file_hash = md5_file( $test_file );
		$result = $this->cache_manager->cache_file_hash( $test_file, $file_hash );
		$this->assertTrue( $result );
		
		// Retrieve cached file hash
		$cached_hash = $this->cache_manager->get_cached_file_hash( $test_file );
		$this->assertEquals( $file_hash, $cached_hash );
		
		// Test with modified file
		file_put_contents( $test_file, "<?php\n// Modified content\necho 'modified';\n" );
		$new_hash = md5_file( $test_file );
		
		// Old hash should still be cached
		$cached_hash = $this->cache_manager->get_cached_file_hash( $test_file );
		$this->assertEquals( $file_hash, $cached_hash );
		$this->assertNotEquals( $new_hash, $cached_hash );
		
		// Update cache with new hash
		$this->cache_manager->cache_file_hash( $test_file, $new_hash );
		$cached_hash = $this->cache_manager->get_cached_file_hash( $test_file );
		$this->assertEquals( $new_hash, $cached_hash );
		
		// Clean up
		$this->cleanup_test_files( $test_files );
	}

	/**
	 * Test cache warming functionality
	 */
	public function test_cache_warming() {
		$warm_data = array(
			'key1' => 'warmed_data_1',
			'key2' => 'warmed_data_2',
			'key3' => 'warmed_data_3'
		);
		
		// Warm the cache
		$result = $this->cache_manager->warm_cache( $warm_data, 'warm_test_group' );
		$this->assertTrue( $result );
		
		// Verify all warmed data is accessible
		foreach ( $warm_data as $key => $expected_data ) {
			$cached_data = $this->cache_manager->get_cached_data( $key, 'warm_test_group' );
			$this->assertEquals( $expected_data, $cached_data );
		}
	}

	/**
	 * Test cache statistics
	 */
	public function test_cache_statistics() {
		// Perform various cache operations
		$this->cache_manager->set_cached_data( 'stats_test_1', 'data1', 300, 'stats_group' );
		$this->cache_manager->set_cached_data( 'stats_test_2', 'data2', 300, 'stats_group' );
		
		// Generate cache hits
		$this->cache_manager->get_cached_data( 'stats_test_1', 'stats_group' );
		$this->cache_manager->get_cached_data( 'stats_test_1', 'stats_group' );
		
		// Generate cache miss
		$this->cache_manager->get_cached_data( 'nonexistent_key', 'stats_group' );
		
		// Get cache statistics
		$stats = $this->cache_manager->get_cache_statistics();
		
		$this->assertIsArray( $stats );
		$this->assertArrayHasKey( 'hits', $stats );
		$this->assertArrayHasKey( 'misses', $stats );
		$this->assertArrayHasKey( 'hit_rate', $stats );
		
		$this->assertGreaterThan( 0, $stats['hits'] );
		$this->assertGreaterThan( 0, $stats['misses'] );
		$this->assertGreaterThan( 0, $stats['hit_rate'] );
		$this->assertLessThanOrEqual( 100, $stats['hit_rate'] );
	}

	/**
	 * Test cache TTL (Time To Live) functionality
	 */
	public function test_cache_ttl() {
		$test_key = 'ttl_test';
		$test_data = 'data with short TTL';
		$short_ttl = 1; // 1 second
		
		// Set cache with short TTL
		$result = $this->cache_manager->set_cached_data( $test_key, $test_data, $short_ttl, 'ttl_group' );
		$this->assertTrue( $result );
		
		// Should be available immediately
		$cached_data = $this->cache_manager->get_cached_data( $test_key, 'ttl_group' );
		$this->assertEquals( $test_data, $cached_data );
		
		// Wait for TTL to expire
		sleep( 2 );
		
		// Should be expired now
		$cached_data = $this->cache_manager->get_cached_data( $test_key, 'ttl_group' );
		$this->assertFalse( $cached_data );
	}

	/**
	 * Test cache size limits and cleanup
	 */
	public function test_cache_size_limits() {
		$large_data_items = array();
		
		// Create large data items
		for ( $i = 1; $i <= 10; $i++ ) {
			$large_data = str_repeat( "Large data item {$i} ", 1000 );
			$key = "large_item_{$i}";
			$large_data_items[ $key ] = $large_data;
			
			$this->cache_manager->set_cached_data( $key, $large_data, 300, 'large_data_group' );
		}
		
		// Get cache size information
		$cache_info = $this->cache_manager->get_cache_info();
		$this->assertIsArray( $cache_info );
		
		// Test cache cleanup
		$cleanup_result = $this->cache_manager->cleanup_cache();
		$this->assertTrue( $cleanup_result );
	}

	/**
	 * Test cache performance
	 */
	public function test_cache_performance() {
		$iterations = 100;
		$test_data = array( 'performance' => 'test', 'iteration' => 0 );
		
		// Measure cache write performance
		$start_time = microtime( true );
		
		for ( $i = 1; $i <= $iterations; $i++ ) {
			$test_data['iteration'] = $i;
			$this->cache_manager->set_cached_data( "perf_test_{$i}", $test_data, 300, 'performance_group' );
		}
		
		$write_time = microtime( true ) - $start_time;
		
		// Measure cache read performance
		$start_time = microtime( true );
		
		for ( $i = 1; $i <= $iterations; $i++ ) {
			$cached_data = $this->cache_manager->get_cached_data( "perf_test_{$i}", 'performance_group' );
		}
		
		$read_time = microtime( true ) - $start_time;
		
		// Performance assertions (should be very fast)
		$this->assertLessThan( 1.0, $write_time, 'Cache write performance is too slow' );
		$this->assertLessThan( 0.5, $read_time, 'Cache read performance is too slow' );
		
		// Read should be faster than write
		$this->assertLessThan( $write_time, $read_time );
	}

	/**
	 * Test cache data serialization
	 */
	public function test_cache_data_serialization() {
		$complex_data = array(
			'string' => 'test string',
			'number' => 12345,
			'array' => array( 1, 2, 3, 'nested' => array( 'deep' => 'value' ) ),
			'object' => (object) array( 'property' => 'value' ),
			'boolean' => true,
			'null' => null
		);
		
		// Cache complex data
		$result = $this->cache_manager->set_cached_data( 'complex_data', $complex_data, 300, 'serialization_group' );
		$this->assertTrue( $result );
		
		// Retrieve and verify data integrity
		$cached_data = $this->cache_manager->get_cached_data( 'complex_data', 'serialization_group' );
		$this->assertEquals( $complex_data, $cached_data );
		
		// Verify specific data types
		$this->assertIsString( $cached_data['string'] );
		$this->assertIsInt( $cached_data['number'] );
		$this->assertIsArray( $cached_data['array'] );
		$this->assertIsObject( $cached_data['object'] );
		$this->assertIsBool( $cached_data['boolean'] );
		$this->assertNull( $cached_data['null'] );
	}

	/**
	 * Test cache error handling
	 */
	public function test_cache_error_handling() {
		// Test with invalid cache group
		$result = $this->cache_manager->set_cached_data( 'test', 'data', 300, '' );
		$this->assertFalse( $result );
		
		// Test with negative TTL
		$result = $this->cache_manager->set_cached_data( 'test', 'data', -1, 'error_group' );
		$this->assertFalse( $result );
		
		// Test getting data with invalid parameters
		$data = $this->cache_manager->get_cached_data( '', 'error_group' );
		$this->assertFalse( $data );
		
		// Test invalidating non-existent cache
		$result = $this->cache_manager->invalidate_cache( 'nonexistent', 'error_group' );
		$this->assertTrue( $result ); // Should return true even if cache doesn't exist
	}

	/**
	 * Clean up after tests
	 */
	public function tearDown(): void {
		// Clear all test cache data
		$this->cache_manager->clear_cache_group( 'test_group' );
		$this->cache_manager->clear_cache_group( 'multi_level' );
		$this->cache_manager->clear_cache_group( 'invalidation_group' );
		$this->cache_manager->clear_cache_group( 'stats_group' );
		$this->cache_manager->clear_cache_group( 'ttl_group' );
		$this->cache_manager->clear_cache_group( 'large_data_group' );
		$this->cache_manager->clear_cache_group( 'performance_group' );
		$this->cache_manager->clear_cache_group( 'serialization_group' );
		$this->cache_manager->clear_cache_group( 'error_group' );
		
		parent::tearDown();
	}
}
