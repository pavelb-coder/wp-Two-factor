<?php
/**
 * OpenSSL encryption/decryption helper.
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Secure_2FA_Open_SSL
 *
 * Handles AES-256-CBC encryption and decryption for sensitive data
 * like TOTP secrets and backup codes.
 */
class WP_Secure_2FA_Open_SSL {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Secure_2FA_Open_SSL|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Secure_2FA_Open_SSL
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Encrypt data using AES-256-CBC.
	 *
	 * @param string $data    Plaintext data.
	 * @param string $key     Encryption key (optional, defaults to auth salt).
	 * @return string|false   Encrypted data as base64, or false on failure.
	 */
	public function encrypt( $data, $key = null ) {
		$key = $key ? $key : $this->get_key();

		if ( ! function_exists( 'openssl_encrypt' ) ) {
			return false;
		}

		$iv     = openssl_random_pseudo_bytes( 16 );
		$cipher = openssl_encrypt(
			$data,
			'AES-256-CBC',
			$key,
			OPENSSL_RAW_DATA,
			$iv
		);

		if ( false === $cipher ) {
			return false;
		}

		return base64_encode( $iv . $cipher );
	}

	/**
	 * Decrypt data using AES-256-CBC.
	 *
	 * @param string $data    Encrypted base64 data.
	 * @param string $key     Encryption key (optional, defaults to auth salt).
	 * @return string|false   Decrypted data, or false on failure.
	 */
	public function decrypt( $data, $key = null ) {
		$key = $key ? $key : $this->get_key();

		if ( ! function_exists( 'openssl_decrypt' ) ) {
			return false;
		}

		$decoded = base64_decode( $data );

		if ( false === $decoded || strlen( $decoded ) <= 16 ) {
			return false;
		}

		$iv     = substr( $decoded, 0, 16 );
		$cipher = substr( $decoded, 16 );

		$plain = openssl_decrypt(
			$cipher,
			'AES-256-CBC',
			$key,
			OPENSSL_RAW_DATA,
			$iv
		);

		if ( false === $plain ) {
			return false;
		}

		return $plain;
	}

	/**
	 * Get the encryption key.
	 *
	 * Uses WordPress auth salt plus a plugin-specific prefix.
	 *
	 * @return string
	 */
	private function get_key() {
		$auth_salt = function_exists( 'wp_salt' ) ? wp_salt( 'auth' ) : '';
		return substr( $auth_salt . 'wps2fa_static_salt', 0, 32 );
	}
}
