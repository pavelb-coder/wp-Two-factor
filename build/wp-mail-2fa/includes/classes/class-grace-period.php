<?php
/**
 * Grace period for 2FA enforcement.
 *
 * @package WP_Mail_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Mail_2FA_Grace_Period
 *
 * Provides a grace period before enforcing 2FA on users who
 * haven't enabled it yet.
 */
class WP_Mail_2FA_Grace_Period {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Mail_2FA_Grace_Period|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Mail_2FA_Grace_Period
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
		add_action( 'admin_notices', array( $this, 'show_grace_notice' ) );
	}

	/**
	 * Check if a user is in grace period.
	 *
	 * @param int $user_id User ID.
	 * @return bool True if in grace period.
	 */
	public function is_in_grace( $user_id ) {
		$settings = WP_Mail_2FA_Settings::get_instance();

		if ( 'yes' !== $settings->get( 'grace_period_enabled' ) ) {
			return false;
		}

		if ( ! $settings->is_enforced( $user_id ) ) {
			return false;
		}

		$helper = WP_Mail_2FA_User_Helper::get_instance();

		// If user already enabled, not in grace.
		if ( $helper->is_enabled( $user_id ) ) {
			return false;
		}

		// Check if grace period start is recorded.
		$grace_start = (int) get_user_meta( $user_id, 'wpm2fa_grace_start', true );

		if ( empty( $grace_start ) ) {
			$grace_start = time();
			update_user_meta( $user_id, 'wpm2fa_grace_start', $grace_start );
		}

		$days     = (int) $settings->get( 'grace_period_days', 7 );
		$deadline = $grace_start + ( $days * DAY_IN_SECONDS );

		return time() < $deadline;
	}

	/**
	 * Get grace period deadline for a user.
	 *
	 * @param int $user_id User ID.
	 * @return int|false Deadline timestamp, or false if not applicable.
	 */
	public function get_deadline( $user_id ) {
		$settings = WP_Mail_2FA_Settings::get_instance();

		if ( 'yes' !== $settings->get( 'grace_period_enabled' ) ) {
			return false;
		}

		$grace_start = (int) get_user_meta( $user_id, 'wpm2fa_grace_start', true );

		if ( empty( $grace_start ) ) {
			return false;
		}

		$days = (int) $settings->get( 'grace_period_days', 7 );

		return $grace_start + ( $days * DAY_IN_SECONDS );
	}

	/**
	 * Show grace period admin notice.
	 */
	public function show_grace_notice() {
		if ( ! is_user_logged_in() ) {
			return;
		}

		$user_id = get_current_user_id();
		$helper  = WP_Mail_2FA_User_Helper::get_instance();

		if ( $helper->is_enabled( $user_id ) ) {
			return;
		}

		$settings = WP_Mail_2FA_Settings::get_instance();

		if ( ! $settings->is_enforced( $user_id ) ) {
			return;
		}

		if ( ! $this->is_in_grace( $user_id ) ) {
			echo '<div class="notice notice-error"><p>'
				. esc_html__( 'Двухфакторная аутентификация теперь обязательна на этом сайте. Пожалуйста, свяжитесь с администратором, если вам нужна помощь с настройкой.', 'wp-mail-2fa' )
				. '</p></div>';
			return;
		}

		$deadline = $this->get_deadline( $user_id );

		if ( $deadline ) {
			$days_left = ceil( ( $deadline - time() ) / DAY_IN_SECONDS );
			$message   = sprintf(
				/* translators: %d: Number of days remaining */
				__( 'Email 2FA будет обязателен через %d дней. Пожалуйста, настройте это сейчас, чтобы избежать сбоев.', 'wp-mail-2fa' ),
				$days_left
			);
		} else {
			$message = __( 'Email 2FA обязателен на этом сайте. Пожалуйста, настройте это сейчас.', 'wp-mail-2fa' );
		}

		echo '<div class="notice notice-warning"><p>' . esc_html( $message ) . '</p>';
		echo '<p><a href="' . esc_url( admin_url( 'profile.php' ) ) . '" class="button">' . esc_html__( 'Настроить 2FA', 'wp-mail-2fa' ) . '</a></p></div>';
	}
}
