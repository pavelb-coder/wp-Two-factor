<?php
/**
 * Core authentication logic.
 *
 * @package WP_Mail_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Mail_2FA_Authentication
 *
 * Handles 2FA code validation for email method.
 */
class WP_Mail_2FA_Authentication {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Mail_2FA_Authentication|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Mail_2FA_Authentication
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
	 * @return array Array with 'success' (bool) and 'method' (string).
	 */
	public function validate( $user_id, $code ) {
		$code = trim( (string) $code );

		if ( empty( $code ) ) {
			return array( 'success' => false, 'method' => '' );
		}

		$email = WP_Mail_2FA_Email::get_instance();

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
		$helper = WP_Mail_2FA_User_Helper::get_instance();

		// If user has 2FA enabled, always require it.
		if ( $helper->is_enabled( $user_id ) ) {
			return true;
		}

		// If enforcement is enabled and applies to this user.
		$settings = WP_Mail_2FA_Settings::get_instance();
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
		$helper = WP_Mail_2FA_User_Helper::get_instance();

		return array(
			'email' => array(
				'key'        => 'email',
				'label'      => __( 'Email verification', 'wp-mail-2fa' ),
				'enabled'    => $helper->is_enabled( $user_id ),
				'configured' => true,
			),
		);
	}
}
