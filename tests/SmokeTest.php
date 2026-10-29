<?php
/**
 * Smoke test: confirm the plugin loads inside the WP test environment.
 *
 * @package WP2FA
 */

namespace WP2FA\Tests;

use WP2FA\Authenticator\Authentication;

/**
 * Class Smoke_Test
 */
class SmokeTest extends \WP_UnitTestCase {

	/**
	 * The plugin main file is loadable and its classes exist.
	 */
	public function test_plugin_classes_available() {
		$this->assertTrue( class_exists( '\\WP2FA\\WP2FA' ), 'WP2FA main class missing' );
		$this->assertTrue( class_exists( '\\WP2FA\\Authenticator\\Authentication' ), 'Authentication class missing' );
		$this->assertTrue( class_exists( '\\WP2FA\\Methods\\Backup_Codes' ), 'Backup_Codes class missing' );
		$this->assertTrue( defined( 'WP_2FA_PREFIX' ), 'WP_2FA_PREFIX constant missing' );
		$this->assertSame( 'wp_2fa_', WP_2FA_PREFIX );
	}
}
