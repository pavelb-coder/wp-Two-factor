<?php
/**
 * AJAX endpoints for 2FA operations.
 *
 * @package WP_Mail_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Mail_2FA_Ajax
 *
 * Handles AJAX requests for email verification.
 */
class WP_Mail_2FA_Ajax {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Mail_2FA_Ajax|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Mail_2FA_Ajax
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
		add_action( 'wp_ajax_wpm2fa_send_email_code', array( $this, 'ajax_send_email_code' ) );
		add_action( 'wp_ajax_wpm2fa_resend_code', array( $this, 'ajax_resend_code' ) );
		add_action( 'wp_ajax_wpm2fa_disable_2fa', array( $this, 'ajax_disable_2fa' ) );
		add_action( 'wp_ajax_wpm2fa_save_settings', array( $this, 'ajax_save_settings' ) );
		add_action( 'wp_ajax_wpm2fa_send_test_email', array( $this, 'ajax_send_test_email' ) );
	}

	/**
	 * Send email 2FA code.
	 */
	public function ajax_send_email_code() {
		check_ajax_referer( 'wpm2fa_nonce', 'nonce' );

		$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : get_current_user_id();

		if ( ! $user_id ) {
			wp_send_json_error( array( 'message' => __( 'Неверный пользователь.', 'wp-mail-2fa' ) ) );
		}

		// Check resend delay.
		$email = WP_Mail_2FA_Email::get_instance();
		if ( $email->has_valid_code( $user_id ) ) {
			$expiry = $email->get_code_expiry( $user_id );
			$settings = WP_Mail_2FA_Settings::get_instance();
			$delay = (int) $settings->get( 'resend_delay_seconds', 60 );

			if ( time() < ( $expiry - $delay ) ) {
				wp_send_json_error( array( 'message' => __( 'Подождите, прежде чем запрашивать другой код.', 'wp-mail-2fa' ) ) );
			}
		}

		$result = $email->send_code( $user_id, 'login' );

		if ( false === $result ) {
			wp_send_json_error( array( 'message' => __( 'Не удалось отправить email. Проверьте настройки email.', 'wp-mail-2fa' ) ) );
		}

		wp_send_json_success( array( 'message' => __( 'Код подтверждения отправлен.', 'wp-mail-2fa' ) ) );
	}

	/**
	 * Resend email code (public endpoint for login page).
	 */
	public function ajax_resend_code() {
		check_ajax_referer( 'wpm2fa_nonce', 'nonce' );

		$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;

		if ( ! $user_id ) {
			wp_send_json_error( array( 'message' => __( 'Неверный пользователь.', 'wp-mail-2fa' ) ) );
		}

		$email = WP_Mail_2FA_Email::get_instance();
		$email->clear_code( $user_id );

		$result = $email->send_code( $user_id, 'login' );

		if ( false === $result ) {
			wp_send_json_error( array( 'message' => __( 'Не удалось отправить email.', 'wp-mail-2fa' ) ) );
		}

		wp_send_json_success( array( 'message' => __( 'Код подтверждения отправлен.', 'wp-mail-2fa' ) ) );
	}

	/**
	 * Disable 2FA for a user.
	 */
	public function ajax_disable_2fa() {
		check_ajax_referer( 'wpm2fa_nonce', 'nonce' );

		if ( ! is_user_logged_in() && ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Не авторизован.', 'wp-mail-2fa' ) ) );
		}

		$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : get_current_user_id();

		if ( ! $user_id ) {
			wp_send_json_error( array( 'message' => __( 'Неверный пользователь.', 'wp-mail-2fa' ) ) );
		}

		WP_Mail_2FA_User_Helper::get_instance()->disable( $user_id );

		wp_send_json_success( array( 'message' => __( '2FA отключён.', 'wp-mail-2fa' ) ) );
	}

	/**
	 * Save settings (admin only).
	 */
	public function ajax_save_settings() {
		check_ajax_referer( 'wpm2fa_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Не авторизован.', 'wp-mail-2fa' ) ) );
		}

		$settings = isset( $_POST['settings'] ) ? $_POST['settings'] : array();
		$sanitized = WP_Mail_2FA_Settings::get_instance()->sanitize( $settings );

		if ( WP_Mail_2FA_Settings::get_instance()->save( $sanitized ) ) {
			wp_send_json_success( array( 'message' => __( 'Настройки сохранены.', 'wp-mail-2fa' ) ) );
		}

		wp_send_json_error( array( 'message' => __( 'Не удалось сохранить настройки.', 'wp-mail-2fa' ) ) );
	}

	/**
	 * Send test email (admin only).
	 */
	public function ajax_send_test_email() {
		check_ajax_referer( 'wpm2fa_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Не авторизован.', 'wp-mail-2fa' ) ) );
		}

		$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : get_current_user_id();

		if ( ! $user_id ) {
			wp_send_json_error( array( 'message' => __( 'Неверный пользователь.', 'wp-mail-2fa' ) ) );
		}

		$email = WP_Mail_2FA_Email::get_instance();
		$result = $email->send_code( $user_id, 'test' );

		if ( false === $result ) {
			wp_send_json_error( array( 'message' => __( 'Не удалось отправить тестовое email.', 'wp-mail-2fa' ) ) );
		}

		wp_send_json_success( array( 'message' => __( 'Тестовое email отправлено.', 'wp-mail-2fa' ) ) );
	}
}
