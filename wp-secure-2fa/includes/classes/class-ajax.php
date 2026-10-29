<?php
/**
 * AJAX endpoints for 2FA operations.
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Secure_2FA_Ajax
 *
 * Handles AJAX requests for TOTP setup, backup codes, email verification, etc.
 */
class WP_Secure_2FA_Ajax {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Secure_2FA_Ajax|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Secure_2FA_Ajax
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor.
	 */
	private function __construct() {
		add_action( 'wp_ajax_wps2fa_generate_totp', array( $this, 'ajax_generate_totp' ) );
		add_action( 'wp_ajax_wps2fa_verify_totp', array( $this, 'ajax_verify_totp' ) );
		add_action( 'wp_ajax_wps2fa_generate_backup_codes', array( $this, 'ajax_generate_backup_codes' ) );
		add_action( 'wp_ajax_wps2fa_send_email_code', array( $this, 'ajax_send_email_code' ) );
		add_action( 'wp_ajax_wps2fa_disable_2fa', array( $this, 'ajax_disable_2fa' ) );
		add_action( 'wp_ajax_wps2fa_save_settings', array( $this, 'ajax_save_settings' ) );
	}

	/**
	 * Generate new TOTP secret.
	 */
	public function ajax_generate_totp() {
		check_ajax_referer( 'wps2fa_nonce', 'nonce' );

		if ( ! is_user_logged_in() ) {
			wp_send_json_error( array( 'message' => __( 'Not logged in.', 'wp-secure-2fa' ) ) );
		}

		$user_id = get_current_user_id();
		$totp    = WP_Secure_2FA_TOTP::get_instance();

		$secret = $totp->generate_secret();

		// Don't store until verified.
		$_SESSION['wps2fa_new_secret'] = $secret;

		$authcode_url = $totp->get_authcode_url(
			WP_Secure_2FA_Settings::get_instance()->get( 'totp_issuer', 'WP Secure 2FA' ),
			get_userdata( $user_id )->user_login
		);

		wp_send_json_success(
			array(
				'secret'         => $secret,
				'authcode_url'   => $authcode_url,
				'current_code'   => $totp->generate( $secret ),
			)
		);
	}

	/**
	 * Verify TOTP code and save secret.
	 */
	public function ajax_verify_totp() {
		check_ajax_referer( 'wps2fa_nonce', 'nonce' );

		if ( ! is_user_logged_in() ) {
			wp_send_json_error( array( 'message' => __( 'Not logged in.', 'wp-secure-2fa' ) ) );
		}

		$user_id = get_current_user_id();
		$code    = isset( $_POST['code'] ) ? sanitize_text_field( $_POST['code'] ) : '';

		if ( empty( $code ) || empty( $_SESSION['wps2fa_new_secret'] ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid request.', 'wp-secure-2fa' ) ) );
		}

		$totp   = WP_Secure_2FA_TOTP::get_instance();
		$secret = $_SESSION['wps2fa_new_secret'];

		if ( ! $totp->verify( $code, $secret ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid code. Please try again.', 'wp-secure-2fa' ) ) );
		}

		// Save secret.
		WP_Secure_2FA_User_Helper::get_instance()->set_totp_secret( $user_id, $secret );
		WP_Secure_2FA_User_Helper::get_instance()->enable_method( $user_id, 'totp' );

		unset( $_SESSION['wps2fa_new_secret'] );

		wp_send_json_success( array( 'message' => __( 'TOTP configured successfully.', 'wp-secure-2fa' ) ) );
	}

	/**
	 * Generate backup codes.
	 */
	public function ajax_generate_backup_codes() {
		check_ajax_referer( 'wps2fa_nonce', 'nonce' );

		if ( ! is_user_logged_in() ) {
			wp_send_json_error( array( 'message' => __( 'Not logged in.', 'wp-secure-2fa' ) ) );
		}

		$user_id = get_current_user_id();
		$backup  = WP_Secure_2FA_Backup_Codes::get_instance();
		$codes   = $backup->generate_for_user( $user_id );

		if ( false === $codes ) {
			wp_send_json_error( array( 'message' => __( 'Failed to generate backup codes.', 'wp-secure-2fa' ) ) );
		}

		WP_Secure_2FA_User_Helper::get_instance()->enable_method( $user_id, 'backup_codes' );

		wp_send_json_success( array( 'codes' => $codes ) );
	}

	/**
	 * Send email verification code.
	 */
	public function ajax_send_email_code() {
		check_ajax_referer( 'wps2fa_nonce', 'nonce' );

		$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : get_current_user_id();

		if ( ! $user_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid user.', 'wp-secure-2fa' ) ) );
		}

		$email = WP_Secure_2FA_Email::get_instance();
		$result = $email->send_code( $user_id, 'login' );

		if ( false === $result ) {
			wp_send_json_error( array( 'message' => __( 'Failed to send email.', 'wp-secure-2fa' ) ) );
		}

		wp_send_json_success( array( 'message' => __( 'Verification code sent.', 'wp-secure-2fa' ) ) );
	}

	/**
	 * Disable 2FA for a user.
	 */
	public function ajax_disable_2fa() {
		check_ajax_referer( 'wps2fa_nonce', 'nonce' );

		if ( ! is_user_logged_in() && ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Not authorized.', 'wp-secure-2fa' ) ) );
		}

		$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : get_current_user_id();

		if ( ! $user_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid user.', 'wp-secure-2fa' ) ) );
		}

		// Clear all 2FA data.
		WP_Secure_2FA_User_Helper::get_instance()->set_enabled_methods( $user_id, array() );
		WP_Secure_2FA_User_Helper::get_instance()->delete_totp_secret( $user_id );
		WP_Secure_2FA_Backup_Codes::get_instance()->delete_for_user( $user_id );
		delete_user_meta( $user_id, 'wps2fa_email_code' );
		delete_user_meta( $user_id, 'wps2fa_email_code_expiry' );

		wp_send_json_success( array( 'message' => __( '2FA disabled.', 'wp-secure-2fa' ) ) );
	}

	/**
	 * Save settings (admin only).
	 */
	public function ajax_save_settings() {
		check_ajax_referer( 'wps2fa_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Not authorized.', 'wp-secure-2fa' ) ) );
		}

		$settings = isset( $_POST['settings'] ) ? $_POST['settings'] : array();
		$sanitized = WP_Secure_2FA_Settings::get_instance()->sanitize( $settings );

		if ( WP_Secure_2FA_Settings::get_instance()->save( $sanitized ) ) {
			wp_send_json_success( array( 'message' => __( 'Settings saved.', 'wp-secure-2fa' ) ) );
		}

		wp_send_json_error( array( 'message' => __( 'Failed to save settings.', 'wp-secure-2fa' ) ) );
	}
}
