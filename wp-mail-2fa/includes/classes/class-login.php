<?php
/**
 * Login flow integration with 2FA.
 *
 * @package WP_Mail_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Mail_2FA_Login
 *
 * Intercepts the WordPress login flow to enforce email-based 2FA.
 */
class WP_Mail_2FA_Login {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Mail_2FA_Login|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Mail_2FA_Login
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
		add_action( 'login_form', array( $this, 'handle_2fa_form' ) );
		add_filter( 'authenticate', array( $this, 'authenticate_2fa' ), 30, 3 );
		add_action( 'login_header', array( $this, 'login_header_hook' ) );
	}

	/**
	 * Handle the 2FA form submission.
	 */
	public function handle_2fa_form() {
		// Check if this is our 2FA form.
		if ( ! isset( $_POST['wpm2fa_action'] ) || 'verify' !== $_POST['wpm2fa_action'] ) {
			return;
		}

		// Verify nonce.
		if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], 'wpm2fa_verify' ) ) {
			wp_die( esc_html__( 'Security check failed.', 'wp-mail-2fa' ) );
		}

		$user_id = isset( $_POST['wpm2fa_user_id'] ) ? absint( $_POST['wpm2fa_user_id'] ) : 0;
		$code    = isset( $_POST['wpm2fa_code'] ) ? sanitize_text_field( $_POST['wpm2fa_code'] ) : '';

		if ( ! $user_id ) {
			wp_die( esc_html__( 'Invalid user.', 'wp-mail-2fa' ) );
		}

		// Validate the code.
		$auth   = WP_Mail_2FA_Authentication::get_instance();
		$result = $auth->validate( $user_id, $code );

		if ( $result['success'] ) {
			// 2FA passed — log the user in.
			wp_set_auth_cookie( $user_id, false, false );
			wp_set_current_user( $user_id );

			// Redirect to admin or custom URL.
			$redirect = isset( $_POST['wpm2fa_redirect'] ) ? sanitize_text_field( $_POST['wpm2fa_redirect'] ) : admin_url();
			wp_safe_redirect( $redirect );
			exit;
		}

		// 2FA failed — show error.
		add_action( 'login_message', array( $this, 'show_2fa_error' ) );
	}

	/**
	 * Show 2FA error message.
	 */
	public function show_2fa_error() {
		echo '<div class="error"><p>' . esc_html__( 'Invalid verification code. Please try again.', 'wp-mail-2fa' ) . '</p></div>';
	}

	/**
	 * Authenticate hook — check if 2FA is needed.
	 *
	 * @param WP_User|WP_Error|null $user     User object or error.
	 * @param string                $username Username.
	 * @param string                $password Password.
	 * @return WP_User|WP_Error
	 */
	public function authenticate_2fa( $user, $username, $password ) {
		// If already an error, return it.
		if ( $user instanceof WP_Error ) {
			return $user;
		}

		// If not a valid user, return.
		if ( ! $user || ! isset( $user->ID ) ) {
			return $user;
		}

		// Check if 2FA is needed.
		$auth = WP_Mail_2FA_Authentication::get_instance();

		if ( ! $auth->needs_2fa( $user->ID ) ) {
			return $user;
		}

		// User has 2FA enabled — block login and show 2FA form.
		return new WP_Error(
			'wpm2fa_required',
			__( 'Two-factor authentication is required to log in.', 'wp-mail-2fa' )
		);
	}

	/**
	 * Login header hook.
	 */
	public function login_header_hook() {
		// Could add custom content to login header.
	}

	/**
	 * Render the 2FA login form.
	 *
	 * @param int $user_id User ID.
	 */
	public function render_2fa_form( $user_id ) {
		// Store user ID in session for the form.
		if ( ! isset( $_SESSION['wpm2fa_user_id'] ) ) {
			$_SESSION['wpm2fa_user_id'] = $user_id;
		}

		include WP_MAIL_2FA_PATH . 'templates/login-2fa.php';
	}

	/**
	 * Check if current request is a 2FA form submission.
	 *
	 * @return bool
	 */
	public function is_2fa_request() {
		return isset( $_GET['action'] ) && 'wpm2fa' === $_GET['action'];
	}
}
