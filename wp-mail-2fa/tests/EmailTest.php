<?php
/**
 * Email code generation and validation tests.
 *
 * @package WP_Mail_2FA
 */

/**
 * Class EmailTest
 */
class EmailTest extends WP_UnitTestCase {

	/**
	 * @var WP_Mail_2FA_Email
	 */
	private $email;

	/**
	 * @var int
	 */
	private $user_id;

	/**
	 * Set up.
	 */
	public function setUp(): void {
		parent::setUp();
		$this->email  = WP_Mail_2FA_Email::get_instance();
		$this->user_id = self::factory()->user->create( array(
			'role'     => 'administrator',
			'user_email' => 'test@example.com',
		) );
	}

	/**
	 * Tear down.
	 */
	public function tearDown(): void {
		$this->email->clear_code( $this->user_id );
		delete_user_meta( $this->user_id, 'wpm2fa_email_code' );
		delete_user_meta( $this->user_id, 'wpm2fa_email_code_expiry' );
		parent::tearDown();
	}

	/**
	 * Test code generation.
	 */
	public function test_generate_code() {
		// Intercept wp_mail to prevent actual email.
		add_filter( 'wp_mail', '__return_true' );

		$code = $this->email->send_code( $this->user_id, 'login' );
		$this->assertNotEmpty( $code );
		$this->assertTrue( ctype_digit( $code ) );
	}

	/**
	 * Test code is stored in user meta.
	 */
	public function test_code_stored() {
		add_filter( 'wp_mail', '__return_true' );

		$code = $this->email->send_code( $this->user_id, 'login' );
		$this->assertEquals( $code, get_user_meta( $this->user_id, 'wpm2fa_email_code', true ) );
	}

	/**
	 * Test code has expiry.
	 */
	public function test_code_expiry() {
		add_filter( 'wp_mail', '__return_true' );

		$code   = $this->email->send_code( $this->user_id, 'login' );
		$expiry = get_user_meta( $this->user_id, 'wpm2fa_email_code_expiry', true );

		$this->assertNotEmpty( $expiry );
		$this->assertGreaterThan( time(), $expiry );
		$this->assertLessThan( time() + 10 * MINUTE_IN_SECONDS, $expiry );
	}

	/**
	 * Test code validation.
	 */
	public function test_validate_valid_code() {
		add_filter( 'wp_mail', '__return_true' );

		$code = $this->email->send_code( $this->user_id, 'login' );
		$this->assertTrue( $this->email->validate_code( $this->user_id, $code ) );
	}

	/**
	 * Test code validation fails on wrong code.
	 */
	public function test_validate_invalid_code() {
		add_filter( 'wp_mail', '__return_true' );

		$this->email->send_code( $this->user_id, 'login' );
		$this->assertFalse( $this->email->validate_code( $this->user_id, '000000' ) );
		$this->assertFalse( $this->email->validate_code( $this->user_id, '999999' ) );
		$this->assertFalse( $this->email->validate_code( $this->user_id, '' ) );
	}

	/**
	 * Test code is consumed after use.
	 */
	public function test_code_consumed() {
		add_filter( 'wp_mail', '__return_true' );

		$code = $this->email->send_code( $this->user_id, 'login' );
		$this->assertTrue( $this->email->validate_code( $this->user_id, $code ) );
		// Code should be gone.
		$this->assertFalse( $this->email->validate_code( $this->user_id, $code ) );
	}

	/**
	 * Test expired code validation fails.
	 */
	public function test_expired_code() {
		add_filter( 'wp_mail', '__return_true' );

		$code = $this->email->send_code( $this->user_id, 'login' );

		// Manually set expiry to past.
		update_user_meta( $this->user_id, 'wpm2fa_email_code_expiry', time() - 1 );

		$this->assertFalse( $this->email->validate_code( $this->user_id, $code ) );
	}

	/**
	 * Test has_valid_code.
	 */
	public function test_has_valid_code() {
		$this->assertFalse( $this->email->has_valid_code( $this->user_id ) );

		add_filter( 'wp_mail', '__return_true' );
		$this->email->send_code( $this->user_id, 'login' );

		$this->assertTrue( $this->email->has_valid_code( $this->user_id ) );
	}

	/**
	 * Test has_valid_code with expired code.
	 */
	public function test_has_valid_code_expired() {
		add_filter( 'wp_mail', '__return_true' );
		$this->email->send_code( $this->user_id, 'login' );

		update_user_meta( $this->user_id, 'wpm2fa_email_code_expiry', time() - 1 );

		$this->assertFalse( $this->email->has_valid_code( $this->user_id ) );
	}

	/**
	 * Test get_code_expiry.
	 */
	public function test_get_code_expiry() {
		$this->assertFalse( $this->email->get_code_expiry( $this->user_id ) );

		add_filter( 'wp_mail', '__return_true' );
		$this->email->send_code( $this->user_id, 'login' );

		$this->assertNotEmpty( $this->email->get_code_expiry( $this->user_id ) );
	}

	/**
	 * Test clear_code.
	 */
	public function test_clear_code() {
		add_filter( 'wp_mail', '__return_true' );
		$this->email->send_code( $this->user_id, 'login' );

		$this->assertTrue( $this->email->has_valid_code( $this->user_id ) );

		$this->email->clear_code( $this->user_id );

		$this->assertFalse( $this->email->has_valid_code( $this->user_id ) );
	}

	/**
	 * Test code with custom length.
	 */
	public function test_custom_code_length() {
		$settings = WP_Mail_2FA_Settings::get_instance();
		$settings->save( array( 'code_length' => 8 ) );

		add_filter( 'wp_mail', '__return_true' );

		$code = $this->email->send_code( $this->user_id, 'login' );
		$this->assertEquals( 8, strlen( $code ) );

		// Restore default.
		$settings->save( array( 'code_length' => 6 ) );
	}
}
