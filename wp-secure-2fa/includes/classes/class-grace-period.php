<?php
/**
 * Grace period for 2FA enforcement.
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Secure_2FA_Grace_Period
 *
 * Provides a grace period before enforcing 2FA on users who
 * haven't configured it yet.
 */
class WP_Secure_2FA_Grace_Period {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Secure_2FA_Grace_Period|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Secure_2FA_Grace_Period
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
		$settings = WP_Secure_2FA_Settings::get_instance();

		if ( 'yes' !== $settings->get( 'grace_period_enabled' ) ) {
			return false;
		}

		if ( ! $settings->is_enforced( $user_id ) ) {
			return false;
		}

		$helper = WP_Secure_2FA_User_Helper::get_instance();

		// If user already configured, not in grace.
		if ( $helper->is_configured( $user_id ) ) {
			return false;
		}

		// Check if grace period start is recorded.
		$grace_start = (int) get_user_meta( $user_id, 'wps2fa_grace_start', true );

		if ( empty( $grace_start ) ) {
			// Start grace period now.
			$grace_start = time();
			update_user_meta( $user_id, 'wps2fa_grace_start', $grace_start );
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
		$settings = WP_Secure_2FA_Settings::get_instance();

		if ( 'yes' !== $settings->get( 'grace_period_enabled' ) ) {
			return false;
		}

		$grace_start = (int) get_user_meta( $user_id, 'wps2fa_grace_start', true );

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
		$helper  = WP_Secure_2FA_User_Helper::get_instance();

		if ( $helper->is_configured( $user_id ) ) {
			return;
		}

		$settings = WP_Secure_2FA_Settings::get_instance();

		if ( ! $settings->is_enforced( $user_id ) ) {
			return;
		}

		if ( ! $this->is_in_grace( $user_id ) ) {
			// Grace period expired — block with notice.
			echo '<div class="notice notice-error"><p>'
				. esc_html__( 'Two-factor authentication is now required on this site. Please contact an administrator if you need help setting it up.', 'wp-secure-2fa' )
				. '</p></div>';
			return;
		}

		$deadline = $this->get_deadline( $user_id );

		if ( $deadline ) {
			$days_left = ceil( ( $deadline - time() ) / DAY_IN_SECONDS );
			$message   = sprintf(
				/* translators: %d: Number of days remaining */
				__( 'Two-factor authentication will be required in %d days. Please set it up now to avoid disruption.', 'wp-secure-2fa' ),
				$days_left
			);
		} else {
			$message = __( 'Two-factor authentication is required on this site. Please set it up now.', 'wp-secure-2fa' );
		}

		echo '<div class="notice notice-warning"><p>' . esc_html( $message ) . '</p>';
		echo '<p><a href="' . esc_url( admin_url( 'profile.php' ) ) . '" class="button">' . esc_html__( 'Set up 2FA', 'wp-secure-2fa' ) . '</a></p></div>';
	}
}
