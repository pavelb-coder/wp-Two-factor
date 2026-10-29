<?php
/**
 * PHPUnit bootstrap for the WP Secure 2FA plugin tests.
 *
 * Loads the WordPress core test suite, then loads the plugin.
 *
 * @package WP_Secure_2FA
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
 */
function wps2fa_activate_plugin() {
	$plugin_file = '/home/user/wp-Two-factor/wp-secure-2fa/wp-secure-2fa.php';

	\wp_register_plugin_realpath( $plugin_file );

	require_once $plugin_file;
}

tests_add_filter( 'muplugins_loaded', 'wps2fa_activate_plugin' );

// Boot WordPress with the test database.
require_once WP_TESTS_DIR . '/includes/bootstrap.php';
