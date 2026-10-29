<?php
/**
 * Smoke test for WP Secure 2FA plugin.
 *
 * @package WP_Secure_2FA
 */

/**
 * Class SmokeTest
 */
class SmokeTest extends WP_UnitTestCase {

	/**
	 * Test that plugin classes are available.
	 */
	public function test_plugin_classes_available() {
		$this->assertTrue(
			class_exists( 'WP_Secure_2FA' ),
			'Main plugin class should exist'
		);
		$this->assertTrue(
			class_exists( 'WP_Secure_2FA_TOTP' ),
			'TOTP class should exist'
		);
		$this->assertTrue(
			class_exists( 'WP_Secure_2FA_Backup_Codes' ),
			'Backup codes class should exist'
		);
		$this->assertTrue(
			class_exists( 'WP_Secure_2FA_Email' ),
			'Email class should exist'
		);
		$this->assertTrue(
			class_exists( 'WP_Secure_2FA_Settings' ),
			'Settings class should exist'
		);
		$this->assertTrue(
			class_exists( 'WP_Secure_2FA_Authentication' ),
			'Authentication class should exist'
		);
		$this->assertTrue(
			class_exists( 'WP_Secure_2FA_Login' ),
			'Login class should exist'
		);
		$this->assertTrue(
			class_exists( 'WP_Secure_2FA_Open_SSL' ),
			'Open_SSL class should exist'
		);
		$this->assertTrue(
			class_exists( 'WP_Secure_2FA_User_Helper' ),
			'User_Helper class should exist'
		);
	}

	/**
	 * Test that main class is instantiable.
	 */
	public function test_main_class_instantiable() {
		$plugin = WP_Secure_2FA::get_instance();
		$this->assertInstanceOf( 'WP_Secure_2FA', $plugin );
	}

	/**
	 * Test that constants are defined.
	 */
	public function test_constants_defined() {
		$this->assertTrue( defined( 'WP_SECURE_2FA_VERSION' ) );
		$this->assertTrue( defined( 'WP_SECURE_2FA_PREFIX' ) );
		$this->assertTrue( defined( 'WP_SECURE_2FA_PATH' ) );
		$this->assertTrue( defined( 'WP_SECURE_2FA_URL' ) );
		$this->assertTrue( defined( 'WP_SECURE_2FA_INC' ) );
	}

	/**
	 * Test that functions exist.
	 */
	public function test_functions_exist() {
		$this->assertTrue( function_exists( 'wp_secure_2fa' ) );
		$this->assertTrue( function_exists( 'wps2fa_get_setting' ) );
		$this->assertTrue( function_exists( 'wps2fa_save_settings' ) );
		$this->assertTrue( function_exists( 'wps2fa_get_user_methods' ) );
		$this->assertTrue( function_exists( 'wps2fa_validate_code' ) );
		$this->assertTrue( function_exists( 'wps2fa_generate_backup_codes' ) );
	}
}
