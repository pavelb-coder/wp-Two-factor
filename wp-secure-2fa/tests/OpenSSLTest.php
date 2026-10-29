<?php
/**
 * OpenSSL encryption tests.
 *
 * @package WP_Secure_2FA
 */

/**
 * Class OpenSSLTest
 */
class OpenSSLTest extends WP_UnitTestCase {

	/**
	 * @var WP_Secure_2FA_Open_SSL
	 */
	private $crypto;

	/**
	 * Set up.
	 */
	public function setUp(): void {
		parent::setUp();
		$this->crypto = WP_Secure_2FA_Open_SSL::get_instance();
	}

	/**
	 * Test encryption and decryption round-trip.
	 */
	public function test_encrypt_decrypt() {
		$plain = 'Hello, World!';
		$enc   = $this->crypto->encrypt( $plain );
		$this->assertNotEmpty( $enc );
		$this->assertNotEquals( $plain, $enc );

		$dec = $this->crypto->decrypt( $enc );
		$this->assertEquals( $plain, $dec );
	}

	/**
	 * Test encryption of empty string.
	 */
	public function test_encrypt_empty() {
		$enc = $this->crypto->encrypt( '' );
		$this->assertNotEmpty( $enc );
		$dec = $this->crypto->decrypt( $enc );
		$this->assertEquals( '', $dec );
	}

	/**
	 * Test encryption of binary data.
	 */
	public function test_encrypt_binary() {
		$binary = random_bytes( 32 );
		$enc    = $this->crypto->encrypt( $binary );
		$dec    = $this->crypto->decrypt( $enc );
		$this->assertEquals( $binary, $dec );
	}

	/**
	 * Test encryption of long data.
	 */
	public function test_encrypt_long_data() {
		$data = str_repeat( 'A', 1000 );
		$enc  = $this->crypto->encrypt( $data );
		$dec  = $this->crypto->decrypt( $enc );
		$this->assertEquals( $data, $dec );
	}

	/**
	 * Test decryption of invalid data returns false.
	 */
	public function test_decrypt_invalid() {
		$this->assertFalse( $this->crypto->decrypt( 'not-valid-base64!!!' ) );
		$this->assertFalse( $this->crypto->decrypt( '' ) );
		$this->assertFalse( $this->crypto->decrypt( 'short' ) );
	}

	/**
	 * Test decryption with wrong key returns false.
	 */
	public function test_decrypt_wrong_key() {
		$enc = $this->crypto->encrypt( 'secret', 'key1' );
		$dec = $this->crypto->decrypt( $enc, 'key2' );
		$this->assertFalse( $dec );
	}

	/**
	 * Test encrypt returns base64 string.
	 */
	public function test_encrypt_returns_base64() {
		$enc = $this->crypto->encrypt( 'test' );
		$this->assertTrue( is_string( $enc ) );
		// Should be valid base64.
		$this->assertNotFalse( base64_decode( $enc, true ) );
	}

	/**
	 * Test encrypt produces different output for different data.
	 */
	public function test_encrypt_different_output() {
		$enc1 = $this->crypto->encrypt( 'data1' );
		$enc2 = $this->crypto->encrypt( 'data2' );
		$this->assertNotEquals( $enc1, $enc2 );
	}

	/**
	 * Test encryption of numbers.
	 */
	public function test_encrypt_numbers() {
		$enc = $this->crypto->encrypt( '1234567890' );
		$dec = $this->crypto->decrypt( $enc );
		$this->assertEquals( '1234567890', $dec );
	}

	/**
	 * Test encryption of special characters.
	 */
	public function test_encrypt_special_chars() {
		$special = 'Hello 世界! 🎉 <script>alert("xss")</script>';
		$enc     = $this->crypto->encrypt( $special );
		$dec     = $this->crypto->decrypt( $enc );
		$this->assertEquals( $special, $dec );
	}
}
