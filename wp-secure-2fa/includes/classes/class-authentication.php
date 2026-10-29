<?php
/**
 * Core authentication logic.
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Secure_2FA_Authentication
 *
 * Handles 2FA code validation across all enabled methods.
 */
class WP_Secure_2FA_Authentication {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Secure_2FA_Authentication|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Secure_2FA_Authentication
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Validate a 2FA code for a user.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Code to validate.
	 * @param string $method  Specific method to check (optional).
	 * @return array Array with 'success' (bool) and 'method' (string).
	 */
	public function validate( $user_id, $code, $method = '' ) {
		$code = trim( (string) $code );

		if ( empty( $code ) ) {
			return array( 'success' => false, 'method' => '' );
		}

		// If a specific method is requested, check only that.
		if ( ! empty( $method ) ) {
			return $this->validate_method( $user_id, $code, $method );
		}

		// Check all enabled methods in order: TOTP, backup codes, email.
		$methods = array( 'totp', 'backup_codes', 'email' );

		foreach ( $methods as $m ) {
			$result = $this->validate_method( $user_id, $code, $m );
			if ( $result['success'] ) {
				return $result;
			}
		}

		return array( 'success' => false, 'method' => '' );
	}

	/**
	 * Validate code against a specific method.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Code to validate.
	 * @param string $method  Method key.
	 * @return array Array with 'success' (bool) and 'method' (string).
	 */
	private function validate_method( $user_id, $code, $method ) {
		switch ( $method ) {
			case 'totp':
				return $this->validate_totp( $user_id, $code );

			case 'backup_codes':
				return $this->validate_backup_codes( $user_id, $code );

			case 'email':
				return $this->validate_email( $user_id, $code );

			default:
				return array( 'success' => false, 'method' => $method );
		}
	}

	/**
	 * Validate TOTP code.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    TOTP code.
	 * @return array
	 */
	private function validate_totp( $user_id, $code ) {
		$secret = WP_Secure_2FA_User_Helper::get_instance()->get_totp_secret( $user_id );

		if ( empty( $secret ) ) {
			return array( 'success' => false, 'method' => 'totp' );
		}

		$settings = WP_Secure_2FA_Settings::get_instance();
		$period    = (int) $settings->get( 'totp_period', 30 );
		$digits    = (int) $settings->get( 'totp_digits', 6 );
		$algorithm = $settings->get( 'totp_algorithm', 'sha1' );
		$window    = 1; // Accept ±1 step.

		$totp = WP_Secure_2FA_TOTP::get_instance();

		if ( $totp->verify( $code, $secret, $window, $period, $digits, $algorithm ) ) {
			return array( 'success' => true, 'method' => 'totp' );
		}

		return array( 'success' => false, 'method' => 'totp' );
	}

	/**
	 * Validate backup code.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Backup code.
	 * @return array
	 */
	private function validate_backup_codes( $user_id, $code ) {
		$backup = WP_Secure_2FA_Backup_Codes::get_instance();

		if ( $backup->validate_code( $user_id, $code ) ) {
			return array( 'success' => true, 'method' => 'backup_codes' );
		}

		return array( 'success' => false, 'method' => 'backup_codes' );
	}

	/**
	 * Validate email code.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Email code.
	 * @return array
	 */
	private function validate_email( $user_id, $code ) {
		$email = WP_Secure_2FA_Email::get_instance();

		if ( $email->validate_code( $user_id, $code ) ) {
			return array( 'success' => true, 'method' => 'email' );
		}

		return array( 'success' => false, 'method' => 'email' );
	}

	/**
	 * Check if a user needs 2FA.
	 *
	 * @param int $user_id User ID.
	 * @return bool True if 2FA is required.
	 */
	public function needs_2fa( $user_id ) {
		$helper = WP_Secure_2FA_User_Helper::get_instance();

		// If user has 2FA configured, always require it.
		if ( $helper->is_configured( $user_id ) ) {
			return true;
		}

		// If enforcement is enabled and applies to this user.
		$settings = WP_Secure_2FA_Settings::get_instance();
		if ( $settings->is_enforced( $user_id ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Get available 2FA methods for a user.
	 *
	 * @param int $user_id User ID.
	 * @return array Array of method data.
	 */
	public function get_available_methods( $user_id ) {
		$settings = WP_Secure_2FA_Settings::get_instance();
		$helper   = WP_Secure_2FA_User_Helper::get_instance();

		$methods = array();

		// TOTP.
		if ( $settings->is_method_enabled( 'enable_totp' ) ) {
			$methods['totp'] = array(
				'key'         => 'totp',
				'label'       => __( 'Authenticator app (TOTP)', 'wp-secure-2fa' ),
				'enabled'     => in_array( 'totp', $helper->get_enabled_methods( $user_id ), true ),
				'configured'  => ! empty( $helper->get_totp_secret( $user_id ) ),
			);
		}

		// Backup codes.
		if ( $settings->is_method_enabled( 'enable_backup_codes' ) ) {
			$methods['backup_codes'] = array(
				'key'        => 'backup_codes',
				'label'      => __( 'Backup codes', 'wp-secure-2fa' ),
				'enabled'    => in_array( 'backup_codes', $helper->get_enabled_methods( $user_id ), true ),
				'configured' => WP_Secure_2FA_Backup_Codes::get_instance()->has_codes( $user_id ),
			);
		}

		// Email.
		if ( $settings->is_method_enabled( 'enable_email' ) ) {
			$methods['email'] = array(
				'key'        => 'email',
				'label'      => __( 'Email verification', 'wp-secure-2fa' ),
				'enabled'    => in_array( 'email', $helper->get_enabled_methods( $user_id ), true ),
				'configured' => true,
			);
		}

		return $methods;
	}
}
