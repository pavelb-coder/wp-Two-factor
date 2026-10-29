<?php
/**
 * Backup codes generation and validation.
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Secure_2FA_Backup_Codes
 *
 * Generates encrypted backup codes for users and validates them
 * during authentication.
 */
class WP_Secure_2FA_Backup_Codes {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Secure_2FA_Backup_Codes|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Secure_2FA_Backup_Codes
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Generate backup codes for a user.
	 *
	 * @param int $user_id User ID.
	 * @return array|false Array of plain backup codes, or false on failure.
	 */
	public function generate_for_user( $user_id ) {
		$codes   = array();
		$plain   = array();
		$encrypted = array();

		for ( $i = 0; $i < 10; $i++ ) {
			$codes[] = $this->generate_code();
		}

		// Encrypt each code.
		$encryptor = WP_Secure_2FA_Open_SSL::get_instance();
		foreach ( $codes as $code ) {
			$encrypted[] = $encryptor->encrypt( $code );
		}

		// Store encrypted codes in user meta.
		$result = update_user_meta( $user_id, 'wps2fa_backup_codes', $encrypted );

		if ( false === $result ) {
			return false;
		}

		// Return plain codes for display.
		return $codes;
	}

	/**
	 * Validate a backup code.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Backup code to validate.
	 * @return bool True if valid (and consumed).
	 */
	public function validate_code( $user_id, $code ) {
		$code = trim( (string) $code );

		if ( empty( $code ) ) {
			return false;
		}

		$encrypted_codes = get_user_meta( $user_id, 'wps2fa_backup_codes', true );

		if ( empty( $encrypted_codes ) || ! is_array( $encrypted_codes ) ) {
			return false;
		}

		$encryptor = WP_Secure_2FA_Open_SSL::get_instance();
		$found_idx = -1;

		foreach ( $encrypted_codes as $idx => $encrypted ) {
			$decrypted = $encryptor->decrypt( $encrypted );
			if ( false !== $decrypted && hash_equals( $decrypted, $code ) ) {
				$found_idx = $idx;
				break;
			}
		}

		if ( -1 === $found_idx ) {
			return false;
		}

		// Consume the code.
		unset( $encrypted_codes[ $found_idx ] );
		update_user_meta( $user_id, 'wps2fa_backup_codes', array_values( $encrypted_codes ) );

		return true;
	}

	/**
	 * Check if a user has backup codes remaining.
	 *
	 * @param int $user_id User ID.
	 * @return bool True if codes remain.
	 */
	public function has_codes( $user_id ) {
		$encrypted_codes = get_user_meta( $user_id, 'wps2fa_backup_codes', true );
		return ! empty( $encrypted_codes ) && is_array( $encrypted_codes ) && count( $encrypted_codes ) > 0;
	}

	/**
	 * Get remaining backup codes count.
	 *
	 * @param int $user_id User ID.
	 * @return int Remaining count.
	 */
	public function get_remaining_count( $user_id ) {
		$encrypted_codes = get_user_meta( $user_id, 'wps2fa_backup_codes', true );
		if ( empty( $encrypted_codes ) || ! is_array( $encrypted_codes ) ) {
			return 0;
		}
		return count( $encrypted_codes );
	}

	/**
	 * Delete all backup codes for a user.
	 *
	 * @param int $user_id User ID.
	 */
	public function delete_for_user( $user_id ) {
		delete_user_meta( $user_id, 'wps2fa_backup_codes' );
	}

	/**
	 * Generate a single backup code.
	 *
	 * @return string 8-character alphanumeric code.
	 */
	private function generate_code() {
		$chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // No ambiguous characters.
		$code  = '';

		for ( $i = 0; $i < 8; $i++ ) {
			$code .= $chars[ random_int( 0, strlen( $chars ) - 1 ) ];
		}

		return $code;
	}
}
