<?php
/**
 * Smoke test for WP Mail 2FA plugin.
 *
 * @package WP_Mail_2FA
 */

/**
 * Class SmokeTest
 */
class SmokeTest extends WP_UnitTestCase {

	/**
	 * Test that plugin classes are available.
	 */
	public function test_plugin_classes_available() {
		$this->assertTrue( class_exists( 'WP_Mail_2FA' ) );
		$this->assertTrue( class_exists( 'WP_Mail_2FA_Email' ) );
		$this->assertTrue( class_exists( 'WP_Mail_2FA_User_Helper' ) );
		$this->assertTrue( class_exists( 'WP_Mail_2FA_Settings' ) );
		$this->assertTrue( class_exists( 'WP_Mail_2FA_Authentication' ) );
		$this->assertTrue( class_exists( 'WP_Mail_2FA_Login' ) );
		$this->assertTrue( class_exists( 'WP_Mail_2FA_Ajax' ) );
		$this->assertTrue( class_exists( 'WP_Mail_2FA_REST_API' ) );
		$this->assertTrue( class_exists( 'WP_Mail_2FA_Grace_Period' ) );
		$this->assertTrue( class_exists( 'WP_Mail_2FA_Admin_Settings_Page' ) );
		$this->assertTrue( class_exists( 'WP_Mail_2FA_Admin_User_Profile' ) );
	}

	/**
	 * Test that main class is instantiable.
	 */
	public function test_main_class_instantiable() {
		$plugin = WP_Mail_2FA::get_instance();
		$this->assertInstanceOf( 'WP_Mail_2FA', $plugin );
	}

	/**
	 * Test that constants are defined.
	 */
	public function test_constants_defined() {
		$this->assertTrue( defined( 'WP_MAIL_2FA_VERSION' ) );
		$this->assertTrue( defined( 'WP_MAIL_2FA_PREFIX' ) );
		$this->assertTrue( defined( 'WP_MAIL_2FA_PATH' ) );
		$this->assertTrue( defined( 'WP_MAIL_2FA_URL' ) );
		$this->assertTrue( defined( 'WP_MAIL_2FA_INC' ) );
	}

	/**
	 * Test that functions exist.
	 */
	public function test_functions_exist() {
		$this->assertTrue( function_exists( 'wp_mail_2fa' ) );
		$this->assertTrue( function_exists( 'wpm2fa_get_setting' ) );
		$this->assertTrue( function_exists( 'wpm2fa_save_settings' ) );
		$this->assertTrue( function_exists( 'wpm2fa_send_email_code' ) );
		$this->assertTrue( function_exists( 'wpm2fa_validate_code' ) );
		$this->assertTrue( function_exists( 'wpm2fa_enable_user_2fa' ) );
		$this->assertTrue( function_exists( 'wpm2fa_disable_user_2fa' ) );
		$this->assertTrue( function_exists( 'wpm2fa_render_login_2fa_form' ) );
	}
}
