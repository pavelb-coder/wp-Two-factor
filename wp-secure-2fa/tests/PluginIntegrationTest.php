<?php
/**
 * Plugin integration tests.
 *
 * @package WP_Secure_2FA
 */

/**
 * Class PluginIntegrationTest
 */
class PluginIntegrationTest extends WP_UnitTestCase {

	/**
	 * @var int
	 */
	private $user_id;

	/**
	 * Set up.
	 */
	public function setUp(): void {
		parent::setUp();
		$this->user_id = self::factory()->user->create( array( 'role' => 'administrator' ) );
	}

	/**
	 * Tear down.
	 */
	public function tearDown(): void {
		wps2fa_disable_user_2fa( $this->user_id );
		delete_user_meta( $this->user_id, 'wps2fa_backup_codes' );
		delete_user_meta( $this->user_id, 'wps2fa_email_code' );
		delete_user_meta( $this->user_id, 'wps2fa_email_code_expiry' );
		delete_user_meta( $this->user_id, 'wps2fa_grace_start' );
		parent::tearDown();
	}

	/**
	 * Test default settings are set.
	 */
	public function test_default_settings() {
		$settings = WP_Secure_2FA_Settings::get_instance();
		$all      = $settings->get_all();

		$this->assertArrayHasKey( 'enable_totp', $all );
		$this->assertArrayHasKey( 'enable_backup_codes', $all );
		$this->assertArrayHasKey( 'enable_email', $all );
		$this->assertEquals( 'yes', $all['enable_totp'] );
		$this->assertEquals( 'yes', $all['enable_backup_codes'] );
		$this->assertEquals( 'yes', $all['enable_email'] );
	}

	/**
	 * Test settings save and retrieve.
	 */
	public function test_settings_save_retrieve() {
		$settings = WP_Secure_2FA_Settings::get_instance();
		$settings->save( array( 'totp_issuer' => 'Test Site' ) );
		$this->assertEquals( 'Test Site', $settings->get( 'totp_issuer' ) );
	}

	/**
	 * Test settings sanitize.
	 */
	public function test_settings_sanitize() {
		$settings = WP_Secure_2FA_Settings::get_instance();
		$sanitized = $settings->sanitize(
			array(
				'enable_totp'         => '1',
				'totp_period'         => 'abc',
				'totp_digits'         => '6',
				'enforce_roles'       => array( 'administrator' ),
			)
		);
		$this->assertEquals( 'yes', $sanitized['enable_totp'] );
		$this->assertEquals( 30, $sanitized['totp_period'] ); // Invalid falls back to default.
		$this->assertEquals( 6, $sanitized['totp_digits'] );
		$this->assertContains( 'administrator', $sanitized['enforce_roles'] );
	}

	/**
	 * Test user helper enable/disable methods.
	 */
	public function test_user_helper_methods() {
		$helper = WP_Secure_2FA_User_Helper::get_instance();

		$this->assertFalse( $helper->is_enabled( $this->user_id ) );

		$helper->enable_method( $this->user_id, 'totp' );
		$this->assertTrue( $helper->is_enabled( $this->user_id ) );
		$this->assertContains( 'totp', $helper->get_enabled_methods( $this->user_id ) );

		$helper->disable_method( $this->user_id, 'totp' );
		$this->assertFalse( $helper->is_enabled( $this->user_id ) );
	}

	/**
	 * Test TOTP setup and verification.
	 */
	public function test_totp_setup_and_verify() {
		$totp   = WP_Secure_2FA_TOTP::get_instance();
		$secret = $totp->generate_secret();

		$helper = WP_Secure_2FA_User_Helper::get_instance();
		$helper->set_totp_secret( $this->user_id, $secret );
		$helper->enable_method( $this->user_id, 'totp' );

		$this->assertTrue( $helper->is_configured( $this->user_id ) );

		$code = $totp->generate( $secret );
		$this->assertTrue( wps2fa_validate_code( $this->user_id, $code, 'totp' ) );
	}

	/**
	 * Test backup codes generation and validation.
	 */
	public function test_backup_codes_flow() {
		$codes = wps2fa_generate_backup_codes( $this->user_id );
		$this->assertNotEmpty( $codes );
		$this->assertTrue( wps2fa_validate_code( $this->user_id, $codes[0], 'backup_codes' ) );
	}

	/**
	 * Test authentication validate method.
	 */
	public function test_authentication_validate() {
		$auth = WP_Secure_2FA_Authentication::get_instance();

		// No methods configured — should fail.
		$result = $auth->validate( $this->user_id, '123456' );
		$this->assertFalse( $result['success'] );

		// Setup TOTP and test.
		$totp   = WP_Secure_2FA_TOTP::get_instance();
		$secret = $totp->generate_secret();
		WP_Secure_2FA_User_Helper::get_instance()->set_totp_secret( $this->user_id, $secret );
		WP_Secure_2FA_User_Helper::get_instance()->enable_method( $this->user_id, 'totp' );

		$code   = $totp->generate( $secret );
		$result = $auth->validate( $this->user_id, $code );
		$this->assertTrue( $result['success'] );
		$this->assertEquals( 'totp', $result['method'] );
	}

	/**
	 * Test needs_2fa.
	 */
	public function test_needs_2fa() {
		$auth = WP_Secure_2FA_Authentication::get_instance();

		// No 2FA configured, no enforcement — should not need 2FA.
		$this->assertFalse( $auth->needs_2fa( $this->user_id ) );

		// Configure TOTP — should need 2FA.
		$totp   = WP_Secure_2FA_TOTP::get_instance();
		$secret = $totp->generate_secret();
		WP_Secure_2FA_User_Helper::get_instance()->set_totp_secret( $this->user_id, $secret );
		$this->assertTrue( $auth->needs_2fa( $this->user_id ) );
	}

	/**
	 * Test get_available_methods.
	 */
	public function test_get_available_methods() {
		$auth = WP_Secure_2FA_Authentication::get_instance();
		$methods = $auth->get_available_methods( $this->user_id );

		$this->assertArrayHasKey( 'totp', $methods );
		$this->assertArrayHasKey( 'backup_codes', $methods );
		$this->assertArrayHasKey( 'email', $methods );

		$this->assertFalse( $methods['totp']['enabled'] );
		$this->assertFalse( $methods['totp']['configured'] );
	}

	/**
	 * Test email code send and validate.
	 */
	public function test_email_code_flow() {
		$email = WP_Secure_2FA_Email::get_instance();
		$code  = $email->send_code( $this->user_id, 'login' );
		$this->assertNotEmpty( $code );
		$this->assertTrue( $email->validate_code( $this->user_id, $code ) );
	}

	/**
	 * Test grace period.
	 */
	public function test_grace_period() {
		$settings = WP_Secure_2FA_Settings::get_instance();
		$settings->save( array( 'enforce_2fa' => 'yes' ) );

		$grace = WP_Secure_2FA_Grace_Period::get_instance();
		$this->assertTrue( $grace->is_in_grace( $this->user_id ) );

		$deadline = $grace->get_deadline( $this->user_id );
		$this->assertNotFalse( $deadline );
	}

	/**
	 * Test REST API routes are registered.
	 */
	public function test_rest_api_routes() {
		global $wp_rest_server;

		// Initialize REST server.
		if ( ! $wp_rest_server ) {
			$wp_rest_server = new WP_REST_Server();
			do_action( 'rest_api_init' );
		}

		$routes = $wp_rest_server->get_routes();
		$this->assertArrayHasKey( '/wps2fa/v1/generate-totp', $routes );
		$this->assertArrayHasKey( '/wps2fa/v1/verify-totp', $routes );
		$this->assertArrayHasKey( '/wps2fa/v1/validate', $routes );
		$this->assertArrayHasKey( '/wps2fa/v1/methods', $routes );
		$this->assertArrayHasKey( '/wps2fa/v1/status', $routes );
		$this->assertArrayHasKey( '/wps2fa/v1/backup-codes', $routes );
		$this->assertArrayHasKey( '/wps2fa/v1/settings', $routes );
	}

	/**
	 * Test admin settings page renders.
	 */
	public function test_admin_settings_page() {
		$page = WP_Secure_2FA_Admin_Settings_Page::get_instance();
		$this->assertInstanceOf( 'WP_Secure_2FA_Admin_Settings_Page', $page );

		// Verify settings page is accessible.
		ob_start();
		$page->render_page();
		$output = ob_get_clean();
		$this->assertStringContainsString( 'WP Secure 2FA Settings', $output );
	}

	/**
	 * Test user profile section renders.
	 */
	public function test_user_profile_section() {
		$user    = get_userdata( $this->user_id );
		$profile = WP_Secure_2FA_Admin_User_Profile::get_instance();

		// Render section (output capture).
		ob_start();
		$profile->render_section( $user );
		$output = ob_get_clean();

		$this->assertStringContainsString( 'Two-Factor Authentication', $output );
	}

	/**
	 * Test setup wizard.
	 */
	public function test_setup_wizard() {
		set_transient( 'wps2fa_setup_wizard', '1', 7 * DAY_IN_SECONDS );
		$wizard = WP_Secure_2FA_Admin_Setup_Wizard::get_instance();
		$this->assertInstanceOf( 'WP_Secure_2FA_Admin_Setup_Wizard', $wizard );

		// Render wizard.
		ob_start();
		$wizard->render_wizard();
		$output = ob_get_clean();

		$this->assertStringContainsString( 'Quick Setup', $output );
		$this->assertStringContainsString( 'Welcome', $output );
	}

	/**
	 * Test top bar banner.
	 */
	public function test_top_bar_banner() {
		$banner = WP_Secure_2FA_Admin_Top_Bar_Banner::get_instance();
		$this->assertInstanceOf( 'WP_Secure_2FA_Admin_Top_Bar_Banner', $banner );

		// Configure 2FA for user.
		$totp   = WP_Secure_2FA_TOTP::get_instance();
		$secret = $totp->generate_secret();
		WP_Secure_2FA_User_Helper::get_instance()->set_totp_secret( $this->user_id, $secret );
		WP_Secure_2FA_User_Helper::get_instance()->enable_method( $this->user_id, 'totp' );

		$status = WP_Secure_2FA_User_Helper::get_instance()->get_status( $this->user_id );
		$this->assertTrue( $status['enabled'] );
		$this->assertTrue( $status['configured'] );
	}

	/**
	 * Test AJAX actions are registered.
	 */
	public function test_ajax_actions() {
		$ajax = WP_Secure_2FA_Ajax::get_instance();
		$this->assertInstanceOf( 'WP_Secure_2FA_Ajax', $ajax );
		$this->assertTrue( method_exists( $ajax, 'ajax_generate_totp' ) );
		$this->assertTrue( method_exists( $ajax, 'ajax_verify_totp' ) );
		$this->assertTrue( method_exists( $ajax, 'ajax_generate_backup_codes' ) );
		$this->assertTrue( method_exists( $ajax, 'ajax_send_email_code' ) );
		$this->assertTrue( method_exists( $ajax, 'ajax_disable_2fa' ) );
		$this->assertTrue( method_exists( $ajax, 'ajax_save_settings' ) );
	}

	/**
	 * Test login form renders.
	 */
	public function test_login_2fa_form_render() {
		$totp   = WP_Secure_2FA_TOTP::get_instance();
		$secret = $totp->generate_secret();
		WP_Secure_2FA_User_Helper::get_instance()->set_totp_secret( $this->user_id, $secret );
		WP_Secure_2FA_User_Helper::get_instance()->enable_method( $this->user_id, 'totp' );

		ob_start();
		wps2fa_render_login_2fa_form( $this->user_id );
		$output = ob_get_clean();

		$this->assertStringContainsString( 'Two-Factor Authentication', $output );
		$this->assertStringContainsString( 'wps2fa-code', $output );
		$this->assertStringContainsString( 'wps2fa_action', $output );
	}
}
