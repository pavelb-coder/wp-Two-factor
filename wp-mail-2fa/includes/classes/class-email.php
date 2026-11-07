<?php
/**
 * Email verification method.
 *
 * @package WP_Mail_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Mail_2FA_Email
 *
 * Generates and validates email-based 2FA codes.
 */
class WP_Mail_2FA_Email {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Mail_2FA_Email|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Mail_2FA_Email
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
		update_user_meta( $user_id, 'wpm2fa_email_code', $code );
		update_user_meta( $user_id, 'wpm2fa_email_code_expiry', time() + 5 * MINUTE_IN_SECONDS );

		// Get settings.
		$settings = WP_Mail_2FA_Settings::get_instance();
		$from_name  = $settings->get( 'email_from_name', get_bloginfo( 'name' ) );
		$subject_prefix = $settings->get( 'email_subject_prefix', '[2FA] ' );
		$code_length = (int) $settings->get( 'code_length', 6 );

		// Adjust code if different length.
		if ( $code_length !== 6 ) {
			$code = str_pad( $code, $code_length, '0', STR_PAD_LEFT );
			$code = substr( $code, -$code_length );
			// Re-generate for correct length.
			$code = '';
			for ( $i = 0; $i < $code_length; $i++ ) {
				$code .= random_int( 0, 9 );
			}
		}

		// Re-store if adjusted.
		if ( $code !== get_user_meta( $user_id, 'wpm2fa_email_code', true ) ) {
			update_user_meta( $user_id, 'wpm2fa_email_code', $code );
		}

		$subject = $subject_prefix . __( 'Ваш код подтверждения 2FA', 'wp-mail-2fa' );
		$message = sprintf(
			__( "Your verification code is: %s\n\nThis code expires in %d minutes.\n\nIf you did not request this, please contact your site administrator.", 'wp-mail-2fa' ),
			$code,
			(int) $settings->get( 'code_expiry_minutes', 5 )
		);

		$headers = array(
			'Content-Type: text/plain; charset=UTF-8',
			'From: ' . $from_name . ' <' . get_option( 'admin_email' ) . '>',
		);

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

		$stored   = get_user_meta( $user_id, 'wpm2fa_email_code', true );
		$expiry   = (int) get_user_meta( $user_id, 'wpm2fa_email_code_expiry', true );

		if ( empty( $stored ) || empty( $expiry ) ) {
			return false;
		}

		if ( time() > $expiry ) {
			// Code expired — clean up.
			delete_user_meta( $user_id, 'wpm2fa_email_code' );
			delete_user_meta( $user_id, 'wpm2fa_email_code_expiry' );
			return false;
		}

		if ( ! hash_equals( $stored, $code ) ) {
			return false;
		}

		// Code valid — consume it.
		delete_user_meta( $user_id, 'wpm2fa_email_code' );
		delete_user_meta( $user_id, 'wpm2fa_email_code_expiry' );

		return true;
	}

	/**
	 * Check if a user has a valid email code stored.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public function has_valid_code( $user_id ) {
		$code   = get_user_meta( $user_id, 'wpm2fa_email_code', true );
		$expiry = (int) get_user_meta( $user_id, 'wpm2fa_email_code_expiry', true );

		if ( empty( $code ) || empty( $expiry ) ) {
			return false;
		}

		return time() < $expiry;
	}

	/**
	 * Get code expiry timestamp.
	 *
	 * @param int $user_id User ID.
	 * @return int|false Expiry timestamp or false.
	 */
	public function get_code_expiry( $user_id ) {
		$expiry = (int) get_user_meta( $user_id, 'wpm2fa_email_code_expiry', true );
		return empty( $expiry ) ? false : $expiry;
	}

	/**
	 * Clear stored code for a user.
	 *
	 * @param int $user_id User ID.
	 */
	public function clear_code( $user_id ) {
		delete_user_meta( $user_id, 'wpm2fa_email_code' );
		delete_user_meta( $user_id, 'wpm2fa_email_code_expiry' );
	}
}
