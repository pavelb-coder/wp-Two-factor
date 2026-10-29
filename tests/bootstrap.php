<?php
/**
 * PHPUnit bootstrap for the WP-Two-factor plugin tests.
 *
 * Loads the WordPress core test suite, then loads the plugin.
 *
 * @package WP2FA
 */

// Path to the WordPress develop checkout (core + test suite).
define( 'WP_TESTS_DIR', '/tmp/wordpress-develop/tests/phpunit' );
define( 'WP_TESTS_CONFIG_FILE_PATH', '/tmp/wordpress-develop/wp-tests-config.php' );

// Load the PHPUnit Polyfills (required by the WP test suite).
require_once '/tmp/wordpress-develop/vendor/yoast/phpunit-polyfills/phpunitpolyfills-autoload.php';

// Load the WP test bootstrap.
require_once WP_TESTS_DIR . '/includes/functions.php';

/**
 * Activate the plugin before the test suite boots.
 *
 * The plugin is symlinked into the WP plugins directory. PHP resolves
 * symlinks in __FILE__, so plugin_basename() needs the real path registered
 * (same mechanism WP core uses when loading plugins from mu-plugins/symlinks).
 */
function wp2fa_activate_plugin() {
	$plugin_file = '/tmp/wordpress-develop/src/wp-content/plugins/wp-Two-factor/wp-2fa.php';

	\wp_register_plugin_realpath( $plugin_file );

	require_once $plugin_file;
}

tests_add_filter( 'muplugins_loaded', 'wp2fa_activate_plugin' );

// Boot WordPress with the test database.
require_once WP_TESTS_DIR . '/includes/bootstrap.php';
