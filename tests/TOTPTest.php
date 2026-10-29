<?php
/**
 * TOTP core tests - RFC 6238 test vectors, key generation, base32.
 *
 * @package WP2FA
 */

namespace WP2FA\Tests;

use WP2FA\Authenticator\Authentication;
use WP2FA\Authenticator\Open_SSL;

/**
 * Class TOTPTest
 */
class TOTPTest extends \WP_UnitTestCase {

	/**
	 * RFC 6238 Appendix B SHA1 test secret (ASCII "12345678901234567890").
	 *
	 * Base32 of that ASCII string is used by authenticator apps.
	 */
	const RFC6238_SECRET_B32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

	/**
	 * RFC 6238 Appendix B SHA256 test secret (ASCII "12345678901234567890123456789012").
	 */
	const RFC6238_SECRET_B32_SHA256 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA';

	/**
	 * RFC 6238 Appendix B SHA512 test secret (ASCII "1234567890123456789012345678901234567890123456789012345678901234").
	 */
	const RFC6238_SECRET_B32_SHA512 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA';

	/**
	 * RFC 6238 expected codes for SHA256 (last-byte truncation).
	 *
	 * The plugin truncates using byte 19 of the HMAC output (the RFC 4226
	 * SHA1 layout), which differs from the RFC 6238 SHA256/SHA512 vectors
	 * that use the last byte. These arrays document the plugin's actual
	 * output for the SHA256/SHA512 secrets, not the RFC 6238 values.
	 */
	const RFC6238_SHA256_PLUGIN_OUTPUT = array(
		59          => '88769542',
		1111111109  => '90349496',
		1111111111  => '36842163',
		1234567890  => '33940707',
		2000000000  => '71384640',
	);

	/**
	 * RFC 6238 expected codes for SHA512 (plugin truncation).
	 */
	const RFC6238_SHA512_PLUGIN_OUTPUT = array(
		59          => '31748108',
		1111111109  => '51041029',
		1111111111  => '68416838',
		1234567890  => '24582871',
		2000000000  => '58982210',
	);

	/**
	 * RFC 6238 Appendix B vectors: time => expected code (SHA1, 8 digits).
	 *
	 * @return array[]
	 */
	public function rfc6238_sha1_vectors() {
		return array(
			't=59'     => array( 59, '94287082' ),
			't=1111111109' => array( 1111111109, '07081804' ),
			't=1111111111' => array( 1111111111, '14050471' ),
			't=1234567890' => array( 1234567890, '89005924' ),
			't=2000000000' => array( 2000000000, '69279037' ),
		);
	}

	/**
	 * Plugin-actual codes for the SHA256 secret (byte-19 truncation, not RFC 6238).
	 *
	 * @return array[]
	 */
	public function plugin_sha256_vectors() {
		return array(
			't=59'     => array( 59, '88769542' ),
			't=1111111109' => array( 1111111109, '90349496' ),
			't=1111111111' => array( 1111111111, '36842163' ),
			't=1234567890' => array( 1234567890, '33940707' ),
			't=2000000000' => array( 2000000000, '71384640' ),
		);
	}

	/**
	 * Plugin-actual codes for the SHA512 secret (byte-19 truncation, not RFC 6238).
	 *
	 * @return array[]
	 */
	public function plugin_sha512_vectors() {
		return array(
			't=59'     => array( 59, '31748108' ),
			't=1111111109' => array( 1111111109, '51041029' ),
			't=1111111111' => array( 1111111111, '68416838' ),
			't=1234567890' => array( 1234567890, '24582871' ),
			't=2000000000' => array( 2000000000, '58982210' ),
		);
	}

	/**
	 * calc_totp reproduces the RFC 6238 test vectors for SHA1.
	 *
	 * @dataProvider rfc6238_sha1_vectors
	 *
	 * @param int    $time  Unix timestamp.
	 * @param string $code  Expected 8-digit code.
	 */
	public function test_calc_totp_rfc6238_sha1( $time, $code ) {
		$step_count = (int) floor( $time / 30 );
		$actual     = Authentication::calc_totp( self::RFC6238_SECRET_B32, $step_count, 8, 'sha1', 30 );
		$this->assertSame( $code, $actual, "TOTP SHA1 mismatch for t={$time}" );
	}

	/**
	 * calc_totp output for the SHA256 secret matches the plugin's actual
	 * (byte-19 truncation) algorithm.
	 *
	 * @dataProvider plugin_sha256_vectors
	 *
	 * @param int    $time  Unix timestamp.
	 * @param string $code  Expected 8-digit code.
	 */
	public function test_calc_totp_sha256_plugin_behavior( $time, $code ) {
		$step_count = (int) floor( $time / 30 );
		$actual     = Authentication::calc_totp( self::RFC6238_SECRET_B32_SHA256, $step_count, 8, 'sha256', 30 );
		$this->assertSame( $code, $actual, "TOTP SHA256 mismatch for t={$time}" );
	}

	/**
	 * calc_totp output for the SHA512 secret matches the plugin's actual
	 * (byte-19 truncation) algorithm.
	 *
	 * @dataProvider plugin_sha512_vectors
	 *
	 * @param int    $time  Unix timestamp.
	 * @param string $code  Expected 8-digit code.
	 */
	public function test_calc_totp_sha512_plugin_behavior( $time, $code ) {
		$step_count = (int) floor( $time / 30 );
		$actual     = Authentication::calc_totp( self::RFC6238_SECRET_B32_SHA512, $step_count, 8, 'sha512', 30 );
		$this->assertSame( $code, $actual, "TOTP SHA512 mismatch for t={$time}" );
	}

	/**
	 * calc_totp with default parameters returns a 6-digit zero-padded code.
	 */
	public function test_calc_totp_default_digits() {
		$code = Authentication::calc_totp( self::RFC6238_SECRET_B32, 1111111109 / 30 );
		$this->assertMatchesRegularExpression( '/^\d{6}$/', $code );
	}

	/**
	 * calc_totp with an invalid base32 secret throws an InvalidArgumentException.
	 */
	public function test_calc_totp_invalid_secret_throws() {
		$this->expectException( \InvalidArgumentException::class );
		Authentication::calc_totp( 'INVALID!KEY!', 1 );
	}

	/**
	 * calc_totp is stable for the same input (deterministic).
	 */
	public function test_calc_totp_deterministic() {
		$a = Authentication::calc_totp( self::RFC6238_SECRET_B32, 123456, 6 );
		$b = Authentication::calc_totp( self::RFC6238_SECRET_B32, 123456, 6 );
		$this->assertSame( $a, $b );
	}

	/**
	 * calc_totp differs for different time steps.
	 */
	public function test_calc_totp_changes_with_time() {
		$a = Authentication::calc_totp( self::RFC6238_SECRET_B32, 100000, 6 );
		$b = Authentication::calc_totp( self::RFC6238_SECRET_B32, 100001, 6 );
		$this->assertNotSame( $a, $b );
	}

	/**
	 * base32_encode of an empty string is empty.
	 */
	public function test_base32_encode_empty() {
		$this->assertSame( '', Authentication::base32_encode( '' ) );
	}

	/**
	 * base32_encode of "foobar" matches the RFC 4648 test vector.
	 */
	public function test_base32_encode_rfc4648() {
		// RFC 4648: "foobar" -> "MZXW6YTBOI======" (with padding).
		// The plugin strips padding, so expect "MZXW6YTBOI".
		$this->assertSame( 'MZXW6YTBOI', Authentication::base32_encode( 'foobar' ) );
	}

	/**
	 * base32_decode of "MZXW6YTBOI" yields "foobar" (RFC 4648 vector, unpadded).
	 */
	public function test_base32_decode_rfc4648() {
		$decoded = Authentication::base32_decode( 'MZXW6YTBOI' );
		$this->assertSame( 'foobar', $decoded );
	}

	/**
	 * base32_decode rejects padded input (plugin does not support '=' padding).
	 */
	public function test_base32_decode_padded_throws() {
		$this->expectException( \InvalidArgumentException::class );
		Authentication::base32_decode( 'MZXW6YTBOI======' );
	}

	/**
	 * base32 roundtrip: encode then decode returns the original string.
	 */
	public function test_base32_roundtrip() {
		$samples = array(
			'hello',
			'world',
			'WP2FA',
			'1234567890',
			'the quick brown fox',
			'\x00\x01\x02\x03\xff',
		);
		foreach ( $samples as $sample ) {
			$encoded = Authentication::base32_encode( $sample );
			$decoded = Authentication::base32_decode( $encoded );
			$this->assertSame( $sample, $decoded, "Roundtrip failed for: {$sample}" );
		}
	}

	/**
	 * base32_decode of a string with invalid characters throws.
	 */
	public function test_base32_decode_invalid_throws() {
		$this->expectException( \InvalidArgumentException::class );
		Authentication::base32_decode( 'INVALID!KEY!' );
	}

	/**
	 * base32_decode is case-insensitive (lowercase accepted).
	 */
	public function test_base32_decode_lowercase() {
		$decoded = Authentication::base32_decode( 'mzxw6ytboi' );
		$this->assertSame( 'foobar', $decoded );
	}

	/**
	 * is_valid_key accepts a valid base32 string.
	 */
	public function test_is_valid_key_accepts_valid() {
		$this->assertTrue( Authentication::is_valid_key( self::RFC6238_SECRET_B32 ) );
	}

	/**
	 * is_valid_key rejects an invalid key.
	 */
	public function test_is_valid_key_rejects_invalid() {
		$this->assertFalse( Authentication::is_valid_key( 'invalid-key!!' ) );
	}

	/**
	 * is_valid_key rejects an empty string.
	 */
	public function test_is_valid_key_rejects_empty() {
		$this->assertFalse( Authentication::is_valid_key( '' ) );
	}

	/**
	 * validate_base32_string accepts valid base32.
	 */
	public function test_validate_base32_string_accepts() {
		$this->assertTrue( Authentication::validate_base32_string( self::RFC6238_SECRET_B32 ) );
	}

	/**
	 * validate_base32_string rejects invalid input.
	 */
	public function test_validate_base32_string_rejects() {
		$this->assertFalse( Authentication::validate_base32_string( 'has spaces 123' ) );
	}

	/**
	 * generate_key returns an encrypted key that is valid when decrypted.
	 */
	public function test_generate_key_returns_encrypted_valid_key() {
		$key = Authentication::generate_key();
		$this->assertNotEmpty( $key );
		$this->assertStringStartsWith( Open_SSL::SECRET_KEY_PREFIX, $key, 'Generated key should be encrypted' );

		// Decrypting yields a valid base32 string.
		$plain = Open_SSL::decrypt( substr( $key, 4 ) );
		$this->assertTrue( Authentication::is_valid_key( $plain ), 'Decrypted key should be valid base32' );
	}

	/**
	 * generate_key with a custom bit size produces a base32 string of the expected length.
	 */
	public function test_generate_key_custom_bitsize() {
		$key = Authentication::generate_key( 80 ); // 80 bits = 10 bytes = 16 base32 chars.
		$plain = Open_SSL::decrypt( substr( $key, 4 ) );
		$this->assertSame( 16, strlen( $plain ), '80 bits should encode to 16 base32 chars' );
	}

	/**
	 * generate_salt returns a base64 string of length 88 (64 bytes base64).
	 */
	public function test_generate_salt() {
		$salt = Authentication::generate_salt();
		$this->assertIsString( $salt );
		$this->assertSame( 88, strlen( $salt ), '64 random bytes base64-encoded = 88 chars' );
	}

	/**
	 * get_code returns a random numeric string of the requested length.
	 */
	public function test_get_code_length() {
		$code = Authentication::get_code( 8 );
		$this->assertSame( 8, strlen( $code ) );
		$this->assertMatchesRegularExpression( '/^\d{8}$/', $code );
	}

	/**
	 * get_code returns different values across calls (randomness).
	 */
	public function test_get_code_random() {
		$a = Authentication::get_code( 12 );
		$b = Authentication::get_code( 12 );
		$this->assertNotSame( $a, $b );
	}

	/**
	 * pack64 converts an integer into an 8-byte big-endian string.
	 */
	public function test_pack64() {
		$packed = Authentication::pack64( 0 );
		$this->assertSame( 8, strlen( $packed ) );
		$this->assertSame( '0000000000000000', bin2hex( $packed ) );

		$packed = Authentication::pack64( 1 );
		$this->assertSame( '0000000000000001', bin2hex( $packed ) );

		$packed = Authentication::pack64( 0x0102030405060708 );
		$this->assertSame( '0102030405060708', bin2hex( $packed ) );
	}

	/**
	 * get_apps returns the supported authenticator apps array.
	 */
	public function test_get_apps() {
		$apps = Authentication::get_apps();
		$this->assertNotEmpty( $apps );
		$this->assertArrayHasKey( 'google', $apps );
		$this->assertArrayHasKey( 'authy', $apps );
		$this->assertArrayHasKey( 'lastpass', $apps );
	}

	/**
	 * is_valid_authcode with the correct current code passes.
	 */
	public function test_is_valid_authcode_correct_code() {
		$key   = self::RFC6238_SECRET_B32;
		$code  = Authentication::calc_totp( $key, floor( time() / 30 ), 6 );
		$valid = Authentication::is_valid_authcode( $key, $code );
		$this->assertTrue( $valid );
	}

	/**
	 * is_valid_authcode with a wrong code fails.
	 */
	public function test_is_valid_authcode_wrong_code() {
		$key  = self::RFC6238_SECRET_B32;
		$code = Authentication::calc_totp( $key, floor( time() / 30 ), 6 );
		// Mutate a digit to be sure it differs.
		$wrong = str_replace( substr( $code, 0, 1 ), $code[0] === '0' ? '1' : '0', $code );
		$this->assertNotSame( $code, $wrong );
		$this->assertFalse( Authentication::is_valid_authcode( $key, $wrong ) );
	}

	/**
	 * is_valid_authcode accepts a code from a neighboring time step (drift allowance).
	 */
	public function test_is_valid_authcode_time_drift() {
		$key  = self::RFC6238_SECRET_B32;
		// Code generated for the previous 30s window should still be accepted.
		$prev_step = (int) floor( ( time() - 30 ) / 30 );
		$code      = Authentication::calc_totp( $key, $prev_step, 6 );
		$this->assertTrue( Authentication::is_valid_authcode( $key, $code ), 'Previous-step code should be accepted within drift allowance' );
	}

	/**
	 * is_valid_authcode rejects an empty key.
	 */
	public function test_is_valid_authcode_empty_key() {
		$this->assertFalse( Authentication::is_valid_authcode( '', '123456' ) );
	}

	/**
	 * is_valid_authcode with a non-string key throws TypeError
	 * (decrypt_key_if_needed requires a string argument).
	 */
	public function test_is_valid_authcode_non_string_key_throws() {
		$this->expectException( \TypeError::class );
		Authentication::is_valid_authcode( null, '123456' );
	}
}
