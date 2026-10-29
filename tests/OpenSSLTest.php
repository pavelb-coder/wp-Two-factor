<?php
/**
 * Open_SSL encryption tests - key encryption/decryption roundtrip.
 *
 * @package WP2FA
 */

namespace WP2FA\Tests;

use WP2FA\Authenticator\Open_SSL;
use WP2FA\Authenticator\Authentication;

/**
 * Class OpenSSLTest
 */
class OpenSSLTest extends \WP_UnitTestCase {

	/**
	 * encrypt/decrypt roundtrip preserves the plaintext.
	 */
	public function test_encrypt_decrypt_roundtrip() {
		$plain = 'hello world';
		$enc   = Open_SSL::encrypt( $plain );
		$dec   = Open_SSL::decrypt( $enc );
		$this->assertSame( $plain, $dec );
	}

	/**
	 * encrypt produces a different value each time (random IV).
	 */
	public function test_encrypt_randomised() {
		$plain = 'same-input';
		$a     = Open_SSL::encrypt( $plain );
		$b     = Open_SSL::encrypt( $plain );
		$this->assertNotSame( $a, $b, 'Encryption should be randomised per call' );
		$this->assertSame( $plain, Open_SSL::decrypt( $a ) );
		$this->assertSame( $plain, Open_SSL::decrypt( $b ) );
	}

	/**
	 * decrypt of a tampered ciphertext throws RuntimeException
	 * (authenticated encryption detects the tampering).
	 */
	public function test_decrypt_tampered_throws() {
		$plain = 'secret-data';
		$enc   = Open_SSL::encrypt( $plain );

		// Flip a byte near the end.
		$tampered = substr( $enc, 0, -1 ) . ( substr( $enc, -1 ) === 'a' ? 'b' : 'a' );

		$this->expectException( \RuntimeException::class );
		Open_SSL::decrypt( $tampered );
	}

	/**
	 * generate_key returns a key prefixed with the SECRET_KEY_PREFIX.
	 */
	public function test_generate_key_prefix() {
		$key = Authentication::generate_key();
		$this->assertStringStartsWith( Open_SSL::SECRET_KEY_PREFIX, $key );
	}

	/**
	 * decrypt_key_if_needed strips the prefix and decrypts to the base32 secret.
	 */
	public function test_decrypt_key_if_needed() {
		$plain = Authentication::base32_encode( 'my-secret-key' );
		$enc   = Open_SSL::SECRET_KEY_PREFIX . Open_SSL::encrypt( $plain );

		$key = $enc;
		$result = Authentication::decrypt_key_if_needed( $key );
		$this->assertSame( $plain, $result, 'decrypt_key_if_needed should return the base32 secret' );
	}

	/**
	 * decrypt_key_if_needed returns the key unchanged when not prefixed.
	 */
	public function test_decrypt_key_if_needed_plain_passthrough() {
		$plain = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
		$key   = $plain;
		$this->assertSame( $plain, Authentication::decrypt_key_if_needed( $key ) );
	}

	/**
	 * is_ssl_available is true on this environment (OpenSSL present).
	 */
	public function test_is_ssl_available() {
		$this->assertTrue( Open_SSL::is_ssl_available() );
	}
}
