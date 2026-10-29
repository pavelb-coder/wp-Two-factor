<?php
/**
 * Email verification method.
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Secure_2FA_Email
 *
 * Generates and validates email-based 2FA codes.
 */
class WP_Secure_2FA_Email {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Secure_2FA_Email|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Secure_2FA_Email
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Generate and send a 2FA code via email.
	 *
	 * @param int    $user_id User ID.
	 * @param string $context Context for the code.
	 * @return string|false The generated code, or false on failure.
	 */
	public function send_code( $user_id, $context = 'login' ) {
		$user = get_userdata( $user_id );

		if ( ! $user || ! $user->user_email ) {
			return false;
		}

		// Generate 6-digit code.
		$code = (string) random_int( 100000, 999999 );

		// Store in user meta with expiry.
		update_user_meta( $user_id, 'wps2fa_email_code', $code );
		update_user_meta( $user_id, 'wps2fa_email_code_expiry', time() + 5 * MINUTE_IN_SECONDS );

		// Send email.
		$subject = __( 'Your 2FA verification code', 'wp-secure-2fa' );
		$message = sprintf(
			__( "Your verification code is: %s\n\nThis code expires in 5 minutes.\n\nIf you did not request this, please contact your site administrator.", 'wp-secure-2fa' ),
			$code
		);

		$headers = array( 'Content-Type: text/plain; charset=UTF-8' );

		$sent = wp_mail( $user->user_email, $subject, $message, $headers );

		return $sent ? $code : false;
	}

	/**
	 * Validate an email 2FA code.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Code to validate.
	 * @return bool True if valid.
	 */
	public function validate_code( $user_id, $code ) {
		$code = trim( (string) $code );

		if ( empty( $code ) ) {
			return false;
		}

		$stored   = get_user_meta( $user_id, 'wps2fa_email_code', true );
		$expiry   = (int) get_user_meta( $user_id, 'wps2fa_email_code_expiry', true );

		if ( empty( $stored ) || empty( $expiry ) ) {
			return false;
		}

		if ( time() > $expiry ) {
			// Code expired.
			delete_user_meta( $user_id, 'wps2fa_email_code' );
			delete_user_meta( $user_id, 'wps2fa_email_code_expiry' );
			return false;
		}

		if ( ! hash_equals( $stored, $code ) ) {
			return false;
		}

		// Code valid — consume it.
		delete_user_meta( $user_id, 'wps2fa_email_code' );
		delete_user_meta( $user_id, 'wps2fa_email_code_expiry' );

		return true;
	}
}
