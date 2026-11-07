<?php
/**
 * Plugin integration tests.
 *
 * @package WP_Mail_2FA
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
		$this->user_id = self::factory()->user->create( array(
			'role'     => 'administrator',
			'user_email' => 'test@example.com',
		) );
	}

	/**
	 * Tear down.
	 */
	public function tearDown(): void {
		wpm2fa_disable_user_2fa( $this->user_id );
		WP_Mail_2FA_Email::get_instance()->clear_code( $this->user_id );
		delete_user_meta( $this->user_id, 'wpm2fa_grace_start' );
		parent::tearDown();
	}

	/**
	 * Test default settings are set.
	 */
	public function test_default_settings() {
		$settings = WP_Mail_2FA_Settings::get_instance();
		$all      = $settings->get_all();

		$this->assertArrayHasKey( 'enforce_2fa', $all );
		$this->assertArrayHasKey( 'code_length', $all );
		$this->assertArrayHasKey( 'code_expiry_minutes', $all );
		$this->assertArrayHasKey( 'resend_delay_seconds', $all );
		$this->assertArrayHasKey( 'grace_period_enabled', $all );
		$this->assertEquals( 6, $all['code_length'] );
		$this->assertEquals( 5, $all['code_expiry_minutes'] );
		$this->assertEquals( 60, $all['resend_delay_seconds'] );
	}

	/**
	 * Test settings save and retrieve.
	 */
	public function test_settings_save_retrieve() {
		$settings = WP_Mail_2FA_Settings::get_instance();
		$settings->save( array( 'email_from_name' => 'Test Site' ) );
		$this->assertEquals( 'Test Site', $settings->get( 'email_from_name' ) );
	}

	/**
	 * Test settings sanitize.
	 */
	public function test_settings_sanitize() {
		$settings = WP_Mail_2FA_Settings::get_instance();
		$sanitized = $settings->sanitize(
			array(
				'enforce_2fa'          => '1',
				'code_length'          => 'abc',
				'code_expiry_minutes'  => '10',
				'email_from_name'      => '<script>alert(1)</script>',
			)
		);
		$this->assertEquals( 'yes', $sanitized['enforce_2fa'] );
		$this->assertEquals( 6, $sanitized['code_length'] ); // Invalid falls back to default.
		$this->assertEquals( 10, $sanitized['code_expiry_minutes'] );
		$sanitized_email_name = sanitize_text_field( '<script>alert(1)</script>' );
		$this->assertStringNotContainsString( '<script>', $sanitized_email_name );
		$this->assertStringNotContainsString( 'alert(1)', $sanitized_email_name );
	}

	/**
	 * Test user helper enable/disable.
	 */
	public function test_user_helper_enable_disable() {
		$helper = WP_Mail_2FA_User_Helper::get_instance();

		$this->assertFalse( $helper->is_enabled( $this->user_id ) );

		$helper->enable( $this->user_id );
		$this->assertTrue( $helper->is_enabled( $this->user_id ) );

		$helper->disable( $this->user_id );
		$this->assertFalse( $helper->is_enabled( $this->user_id ) );
	}

	/**
	 * Test user helper status.
	 */
	public function test_user_helper_status() {
		$helper = WP_Mail_2FA_User_Helper::get_instance();
		$status = $helper->get_status( $this->user_id );

		$this->assertFalse( $status['enabled'] );
		$this->assertTrue( $status['has_email'] );
		$this->assertEquals( 'test@example.com', $status['email'] );

		$helper->enable( $this->user_id );
		$status = $helper->get_status( $this->user_id );
		$this->assertTrue( $status['enabled'] );
	}

	/**
	 * Test authentication validate.
	 */
	public function test_authentication_validate() {
		$auth = WP_Mail_2FA_Authentication::get_instance();

		// No code — should fail.
		$result = $auth->validate( $this->user_id, '123456' );
		$this->assertFalse( $result['success'] );

		// Send code and validate.
		add_filter( 'wp_mail', '__return_true' );
		$email = WP_Mail_2FA_Email::get_instance();
		$code  = $email->send_code( $this->user_id, 'login' );

		$result = $auth->validate( $this->user_id, $code );
		$this->assertTrue( $result['success'] );
		$this->assertEquals( 'email', $result['method'] );
	}

	/**
	 * Test needs_2fa.
	 */
	public function test_needs_2fa() {
		$auth = WP_Mail_2FA_Authentication::get_instance();

		// No 2FA enabled, no enforcement — should not need 2FA.
		$this->assertFalse( $auth->needs_2fa( $this->user_id ) );

		// Enable 2FA for user — should need 2FA.
		WP_Mail_2FA_User_Helper::get_instance()->enable( $this->user_id );
		$this->assertTrue( $auth->needs_2fa( $this->user_id ) );
	}

	/**
	 * Test needs_2fa with enforcement.
	 */
	public function test_needs_2fa_enforced() {
		$settings = WP_Mail_2FA_Settings::get_instance();
		$settings->save( array( 'enforce_2fa' => 'yes' ) );

		$auth = WP_Mail_2FA_Authentication::get_instance();
		$this->assertTrue( $auth->needs_2fa( $this->user_id ) );
	}

	/**
	 * Test get_available_methods.
	 */
	public function test_get_available_methods() {
		$auth    = WP_Mail_2FA_Authentication::get_instance();
		$methods = $auth->get_available_methods( $this->user_id );

		$this->assertArrayHasKey( 'email', $methods );
		$this->assertFalse( $methods['email']['enabled'] );

		WP_Mail_2FA_User_Helper::get_instance()->enable( $this->user_id );
		$methods = $auth->get_available_methods( $this->user_id );
		$this->assertTrue( $methods['email']['enabled'] );
	}

	/**
	 * Test grace period.
	 */
	public function test_grace_period() {
		$settings = WP_Mail_2FA_Settings::get_instance();
		$settings->save( array( 'enforce_2fa' => 'yes' ) );

		$grace = WP_Mail_2FA_Grace_Period::get_instance();
		$this->assertTrue( $grace->is_in_grace( $this->user_id ) );

		$deadline = $grace->get_deadline( $this->user_id );
		$this->assertNotFalse( $deadline );
	}

	/**
	 * Test grace period when user has 2FA enabled.
	 */
	public function test_grace_period_not_in_grace_when_enabled() {
		$settings = WP_Mail_2FA_Settings::get_instance();
		$settings->save( array( 'enforce_2fa' => 'yes' ) );

		WP_Mail_2FA_User_Helper::get_instance()->enable( $this->user_id );

		$grace = WP_Mail_2FA_Grace_Period::get_instance();
		$this->assertFalse( $grace->is_in_grace( $this->user_id ) );
	}

	/**
	 * Test REST API routes are registered.
	 */
	public function test_rest_api_routes() {
		global $wp_rest_server;

		if ( ! $wp_rest_server ) {
			$wp_rest_server = new WP_REST_Server();
			do_action( 'rest_api_init' );
		}

		$routes = $wp_rest_server->get_routes();
		$this->assertArrayHasKey( '/wpm2fa/v1/send-code', $routes );
		$this->assertArrayHasKey( '/wpm2fa/v1/validate', $routes );
		$this->assertArrayHasKey( '/wpm2fa/v1/methods', $routes );
		$this->assertArrayHasKey( '/wpm2fa/v1/status', $routes );
		$this->assertArrayHasKey( '/wpm2fa/v1/disable', $routes );
		$this->assertArrayHasKey( '/wpm2fa/v1/settings', $routes );
	}

	/**
	 * Test admin settings page renders.
	 */
	public function test_admin_settings_page() {
		$page = WP_Mail_2FA_Admin_Settings_Page::get_instance();
		$this->assertInstanceOf( 'WP_Mail_2FA_Admin_Settings_Page', $page );

		ob_start();
		$page->render_page();
		$output = ob_get_clean();

		$this->assertStringContainsString( 'Настройки WP Mail 2FA', $output );
		$this->assertStringContainsString( 'code_length', $output );
		$this->assertStringContainsString( 'enforce_2fa', $output );
	}

	/**
	 * Test user profile section renders.
	 */
	public function test_user_profile_section() {
		wp_set_current_user( $this->user_id );

		$user    = get_userdata( $this->user_id );
		$profile = WP_Mail_2FA_Admin_User_Profile::get_instance();

		ob_start();
		$profile->render_section( $user );
		$output = ob_get_clean();

		$this->assertStringContainsString( 'Двухфакторная аутентификация по email', $output );
	}

	/**
	 * Test AJAX class methods exist.
	 */
	public function test_ajax_class() {
		$ajax = WP_Mail_2FA_Ajax::get_instance();
		$this->assertInstanceOf( 'WP_Mail_2FA_Ajax', $ajax );
		$this->assertTrue( method_exists( $ajax, 'ajax_send_email_code' ) );
		$this->assertTrue( method_exists( $ajax, 'ajax_resend_code' ) );
		$this->assertTrue( method_exists( $ajax, 'ajax_disable_2fa' ) );
		$this->assertTrue( method_exists( $ajax, 'ajax_save_settings' ) );
		$this->assertTrue( method_exists( $ajax, 'ajax_send_test_email' ) );
	}

	/**
	 * Test login 2FA form renders.
	 */
	public function test_login_2fa_form_render() {
		WP_Mail_2FA_User_Helper::get_instance()->enable( $this->user_id );

		add_filter( 'wp_mail', '__return_true' );
		$email = WP_Mail_2FA_Email::get_instance();
		$email->send_code( $this->user_id, 'login' );

		ob_start();
		wpm2fa_render_login_2fa_form( $this->user_id );
		$output = ob_get_clean();

		$this->assertStringContainsString( 'Подтверждение по email', $output );
		$this->assertStringContainsString( 'wpm2fa-code', $output );
		$this->assertStringContainsString( 'wpm2fa_action', $output );
	}

	/**
	 * Test core functions.
	 */
	public function test_core_functions() {
		// Test wpm2fa_send_email_code.
		add_filter( 'wp_mail', '__return_true' );
		$code = wpm2fa_send_email_code( $this->user_id );
		$this->assertNotEmpty( $code );

		// Test wpm2fa_validate_code.
		$this->assertTrue( wpm2fa_validate_code( $this->user_id, $code ) );

		// Test wpm2fa_enable_user_2fa.
		wpm2fa_enable_user_2fa( $this->user_id );
		$this->assertTrue( wpm2fa_get_user_status( $this->user_id )['enabled'] );

		// Test wpm2fa_disable_user_2fa.
		wpm2fa_disable_user_2fa( $this->user_id );
		$this->assertFalse( wpm2fa_get_user_status( $this->user_id )['enabled'] );
	}
}
