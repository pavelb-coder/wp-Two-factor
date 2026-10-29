<?php
/**
 * User helper functions for 2FA management.
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Secure_2FA_User_Helper
 *
 * Manages per-user 2FA settings, method selection, and status.
 */
class WP_Secure_2FA_User_Helper {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Secure_2FA_User_Helper|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Secure_2FA_User_Helper
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Get enabled methods for a user.
	 *
	 * @param int $user_id User ID.
	 * @return array Array of enabled method keys.
	 */
	public function get_enabled_methods( $user_id ) {
		$methods = get_user_meta( $user_id, 'wps2fa_enabled_methods', true );

		if ( empty( $methods ) || ! is_array( $methods ) ) {
			return array();
		}

		return $methods;
	}

	/**
	 * Set enabled methods for a user.
	 *
	 * @param int   $user_id User ID.
	 * @param array $methods Array of method keys.
	 */
	public function set_enabled_methods( $user_id, $methods ) {
		update_user_meta( $user_id, 'wps2fa_enabled_methods', $methods );
	}

	/**
	 * Add a method to a user's enabled methods.
	 *
	 * @param int    $user_id User ID.
	 * @param string $method  Method key.
	 */
	public function enable_method( $user_id, $method ) {
		$methods   = $this->get_enabled_methods( $user_id );
		$methods[] = $method;
		$this->set_enabled_methods( $user_id, array_unique( $methods ) );
	}

	/**
	 * Remove a method from a user's enabled methods.
	 *
	 * @param int    $user_id User ID.
	 * @param string $method  Method key.
	 */
	public function disable_method( $user_id, $method ) {
		$methods = $this->get_enabled_methods( $user_id );
		$methods = array_diff( $methods, array( $method ) );
		$this->set_enabled_methods( $user_id, array_values( $methods ) );
	}

	/**
	 * Check if a user has 2FA enabled.
	 *
	 * @param int $user_id User ID.
	 * @return bool True if any method is enabled.
	 */
	public function is_enabled( $user_id ) {
		$methods = $this->get_enabled_methods( $user_id );
		return ! empty( $methods );
	}

	/**
	 * Check if a user has 2FA configured.
	 *
	 * @param int $user_id User ID.
	 * @return bool True if TOTP secret or backup codes exist.
	 */
	public function is_configured( $user_id ) {
		$totp_secret = get_user_meta( $user_id, 'wps2fa_totp_secret', true );
		$backup      = WP_Secure_2FA_Backup_Codes::get_instance()->has_codes( $user_id );

		return ! empty( $totp_secret ) || $backup;
	}

	/**
	 * Store TOTP secret for a user.
	 *
	 * @param int    $user_id User ID.
	 * @param string $secret  Base32 encoded secret.
	 */
	public function set_totp_secret( $user_id, $secret ) {
		update_user_meta( $user_id, 'wps2fa_totp_secret', $secret );
	}

	/**
	 * Get TOTP secret for a user.
	 *
	 * @param int $user_id User ID.
	 * @return string|false Secret, or false if not set.
	 */
	public function get_totp_secret( $user_id ) {
		return get_user_meta( $user_id, 'wps2fa_totp_secret', true );
	}

	/**
	 * Delete TOTP secret for a user.
	 *
	 * @param int $user_id User ID.
	 */
	public function delete_totp_secret( $user_id ) {
		delete_user_meta( $user_id, 'wps2fa_totp_secret' );
	}

	/**
	 * Get user's 2FA status summary.
	 *
	 * @param int $user_id User ID.
	 * @return array Status array.
	 */
	public function get_status( $user_id ) {
		$methods    = $this->get_enabled_methods( $user_id );
		$configured = $this->is_configured( $user_id );
		$backup_count = WP_Secure_2FA_Backup_Codes::get_instance()->get_remaining_count( $user_id );

		return array(
			'enabled'      => ! empty( $methods ),
			'configured'   => $configured,
			'methods'      => $methods,
			'backup_count' => $backup_count,
		);
	}
}
