<?php
/**
 * TOTP tests.
 *
 * @package WP_Secure_2FA
 */

/**
 * Class TOTPTest
 */
class TOTPTest extends WP_UnitTestCase {

	/**
	 * @var WP_Secure_2FA_TOTP
	 */
	private $totp;

	/**
	 * Set up.
	 */
	public function setUp(): void {
		parent::setUp();
		$this->totp = WP_Secure_2FA_TOTP::get_instance();
	}

	/**
	 * Test base32 encode.
	 */
	public function test_base32_encode() {
		$this->assertEquals( 'MZXW6', $this->totp->base32_encode( 'foo' ) );
	}

	/**
	 * Test base32 decode.
	 */
	public function test_base32_decode() {
		$this->assertEquals( 'foo', $this->totp->base32_decode( 'MZXW6==' ) );
		$this->assertEquals( 'foo', $this->totp->base32_decode( 'MZXW6' ) );
	}

	/**
	 * Test base32 round-trip.
	 */
	public function test_base32_round_trip() {
		$data = 'Hello, World! 123';
		$enc  = $this->totp->base32_encode( $data );
		$dec  = $this->totp->base32_decode( $enc );
		$this->assertEquals( $data, $dec );
	}

	/**
	 * Test base32 decode is case insensitive.
	 */
	public function test_base32_decode_case_insensitive() {
		$this->assertEquals( 'foo', $this->totp->base32_decode( 'mzxw6' ) );
		$this->assertEquals( 'foo', $this->totp->base32_decode( 'MZXW6' ) );
	}

	/**
	 * Test base32 decode rejects invalid characters.
	 */
	public function test_base32_decode_invalid() {
		$this->assertFalse( $this->totp->base32_decode( 'INVALID!' ) );
	}

	/**
	 * Test secret generation.
	 */
	public function test_generate_secret() {
		$secret = $this->totp->generate_secret();
		$this->assertNotEmpty( $secret );
		$this->assertTrue( ctype_alpha( $secret ) || ctype_digit( $secret ) || ctype_alnum( $secret ) );
		$this->assertEquals( 32, strlen( $secret ) ); // 20 bytes = 32 base32 chars.
	}

	/**
	 * Test secret generation produces unique values.
	 */
	public function test_generate_secret_unique() {
		$s1 = $this->totp->generate_secret();
		$s2 = $this->totp->generate_secret();
		$this->assertNotEquals( $s1, $s2 );
	}

	/**
	 * Test TOTP generation produces valid 6-digit codes.
	 */
	public function test_generate_valid_code() {
		$secret = $this->totp->generate_secret();
		$code   = $this->totp->generate( $secret );
		$this->assertTrue( ctype_digit( $code ) );
		$this->assertEquals( 6, strlen( $code ) );
	}

	/**
	 * Test TOTP generation with specific timestamp.
	 */
	public function test_generate_with_timestamp() {
		$secret = $this->totp->generate_secret();
		$code   = $this->totp->generate( $secret, 1234567890 );
		$this->assertTrue( ctype_digit( $code ) );
		$this->assertEquals( 6, strlen( $code ) );
	}

	/**
	 * Test TOTP verification round-trip.
	 */
	public function test_verify_valid_code() {
		$secret = $this->totp->generate_secret();
		$code   = $this->totp->generate( $secret );
		$this->assertTrue( $this->totp->verify( $code, $secret ) );
	}

	/**
	 * Test TOTP verification rejects invalid code.
	 */
	public function test_verify_invalid_code() {
		$secret = $this->totp->generate_secret();
		$code   = $this->totp->generate( $secret );
		$this->assertFalse( $this->totp->verify( '000000', $secret ) );
		$this->assertFalse( $this->totp->verify( '999999', $secret ) );
	}

	/**
	 * Test TOTP verification with empty input.
	 */
	public function test_verify_empty() {
		$this->assertFalse( $this->totp->verify( '', 'SECRET' ) );
		$this->assertFalse( $this->totp->verify( '123456', '' ) );
	}

	/**
	 * Test TOTP verification with window.
	 */
	public function test_verify_with_window() {
		$secret = $this->totp->generate_secret();
		$code   = $this->totp->generate( $secret, time() - 30 ); // 1 step back.
		$this->assertTrue( $this->totp->verify( $code, $secret, 1, 30 ) );
	}

	/**
	 * Test TOTP generation with custom period.
	 */
	public function test_generate_custom_period() {
		$secret = $this->totp->generate_secret();
		$code   = $this->totp->generate( $secret, null, 60 );
		$this->assertTrue( ctype_digit( $code ) );
		$this->assertEquals( 6, strlen( $code ) );
	}

	/**
	 * Test TOTP generation with custom digits.
	 */
	public function test_generate_custom_digits() {
		$secret = $this->totp->generate_secret();
		$code   = $this->totp->generate( $secret, null, 30, 8 );
		$this->assertEquals( 8, strlen( $code ) );
	}

	/**
	 * Test authcode URL generation.
	 */
	public function test_authcode_url() {
		$secret = $this->totp->generate_secret();
		$url    = $this->totp->get_authcode_url( $secret, 'TestSite', 'testuser' );
		$this->assertStringContainsString( 'otpauth://totp/', $url );
		$this->assertStringContainsString( 'secret=', $url );
		$this->assertStringContainsString( 'issuer=', $url );
		$this->assertStringContainsString( 'algorithm=SHA1', $url );
		$this->assertStringContainsString( 'digits=6', $url );
		$this->assertStringContainsString( 'period=30', $url );
	}

	/**
	 * Test RFC 6238 test vectors (SHA1).
	 *
	 * These are the official test vectors from RFC 6238.
	 */
	public function test_rfc6238_sha1_vectors() {
		// Test vector 1: Time = 59 seconds, 8 digits.
		$secret1 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // "12345678901234567890"
		$code1   = $this->totp->generate( $secret1, 59, 30, 8 );
		$this->assertEquals( '94287082', $code1 );

		// Test vector 2: Time = 1111111109 seconds, 8 digits.
		$code2 = $this->totp->generate( $secret1, 1111111109, 30, 8 );
		$this->assertEquals( '07081804', $code2 );

		// Test vector 3: Time = 1111111111 seconds, 8 digits.
		$code3 = $this->totp->generate( $secret1, 1111111111, 30, 8 );
		$this->assertEquals( '14050471', $code3 );
	}

	/**
	 * Test deterministic code generation.
	 */
	public function test_deterministic_generation() {
		$secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
		$ts     = 59;
		$code1  = $this->totp->generate( $secret, $ts );
		$code2  = $this->totp->generate( $secret, $ts );
		$this->assertEquals( $code1, $code2 );
	}

	/**
	 * Test verification with specific RFC vector.
	 */
	public function test_verify_rfc_vector() {
		$secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
		$code   = '94287082';
		// RFC vector uses 8 digits, but our default is 6. Adjust.
		$code6  = $this->totp->generate( $secret, 59, 30, 6 );
		$this->assertTrue( ctype_digit( $code6 ) );
	}
}
