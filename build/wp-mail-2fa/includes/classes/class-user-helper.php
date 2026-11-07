<?php
/**
 * User helper functions for 2FA management.
 *
 * @package WP_Mail_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Mail_2FA_User_Helper
 *
 * Manages per-user 2FA settings and status.
 */
class WP_Mail_2FA_User_Helper {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Mail_2FA_User_Helper|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Mail_2FA_User_Helper
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Check if user has email 2FA enabled.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public function is_enabled( $user_id ) {
		return 'yes' === get_user_meta( $user_id, 'wpm2fa_email_enabled', true );
	}

	/**
	 * Enable email 2FA for a user.
	 *
	 * @param int $user_id User ID.
	 */
	public function enable( $user_id ) {
		update_user_meta( $user_id, 'wpm2fa_email_enabled', 'yes' );
	}

	/**
	 * Disable email 2FA for a user.
	 *
	 * @param int $user_id User ID.
	 */
	public function disable( $user_id ) {
		update_user_meta( $user_id, 'wpm2fa_email_enabled', 'no' );
		WP_Mail_2FA_Email::get_instance()->clear_code( $user_id );
	}

	/**
	 * Get user's 2FA status summary.
	 *
	 * @param int $user_id User ID.
	 * @return array
	 */
	public function get_status( $user_id ) {
		$enabled = $this->is_enabled( $user_id );
		$email   = get_userdata( $user_id );

		return array(
			'enabled'      => $enabled,
			'has_email'    => $email && ! empty( $email->user_email ),
			'email'        => $email ? $email->user_email : '',
		);
	}
}
