<?php
/**
 * Login flow integration with 2FA.
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Secure_2FA_Login
 *
 * Intercepts the WordPress login flow to enforce 2FA.
 */
class WP_Secure_2FA_Login {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Secure_2FA_Login|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Secure_2FA_Login
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
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ) );
		add_action( 'login_header', array( $this, 'login_header_hook' ) );
	}

	/**
	 * Handle the 2FA form submission.
	 */
	public function handle_2fa_form() {
		// Check if this is our 2FA form.
		if ( ! isset( $_POST['wps2fa_action'] ) || 'verify' !== $_POST['wps2fa_action'] ) {
			return;
		}

		// Verify nonce.
		if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], 'wps2fa_verify' ) ) {
			wp_die( esc_html__( 'Security check failed.', 'wp-secure-2fa' ) );
		}

		$user_id = isset( $_POST['wps2fa_user_id'] ) ? absint( $_POST['wps2fa_user_id'] ) : 0;
		$code    = isset( $_POST['wps2fa_code'] ) ? sanitize_text_field( $_POST['wps2fa_code'] ) : '';
		$method  = isset( $_POST['wps2fa_method'] ) ? sanitize_text_field( $_POST['wps2fa_method'] ) : '';

		if ( ! $user_id ) {
			wp_die( esc_html__( 'Invalid user.', 'wp-secure-2fa' ) );
		}

		// Validate the code.
		$auth = WP_Secure_2FA_Authentication::get_instance();
		$result = $auth->validate( $user_id, $code, $method );

		if ( $result['success'] ) {
			// 2FA passed — log the user in.
			wp_set_auth_cookie( $user_id, false, false );
			wp_set_current_user( $user_id );

			// Redirect to admin.
			$redirect = isset( $_POST['wps2fa_redirect'] ) ? sanitize_text_field( $_POST['wps2fa_redirect'] ) : admin_url();
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
		echo '<div class="error"><p>' . esc_html__( 'Invalid verification code. Please try again.', 'wp-secure-2fa' ) . '</p></div>';
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
		$auth = WP_Secure_2FA_Authentication::get_instance();

		if ( ! $auth->needs_2fa( $user->ID ) ) {
			return $user;
		}

		// Check if user has 2FA configured.
		$helper = WP_Secure_2FA_User_Helper::get_instance();

		if ( ! $helper->is_configured( $user->ID ) ) {
			// User needs to set up 2FA — redirect to setup.
			return new WP_Error(
				'wps2fa_setup_required',
				__( 'Two-factor authentication is required. Please complete setup.', 'wp-secure-2fa' )
			);
		}

		// User has 2FA configured — block login and show 2FA form.
		return new WP_Error(
			'wps2fa_required',
			__( 'Two-factor authentication is required to log in.', 'wp-secure-2fa' )
		);
	}

	/**
	 * Login failed hook.
	 *
	 * @param string $username Username.
	 */
	public function on_login_failed( $username ) {
		// Could log failed attempts here.
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
		$auth     = WP_Secure_2FA_Authentication::get_instance();
		$methods  = $auth->get_available_methods( $user_id );

		// Store user ID in session for the form.
		if ( ! isset( $_SESSION['wps2fa_user_id'] ) ) {
			$_SESSION['wps2fa_user_id'] = $user_id;
		}

		include WP_SECURE_2FA_PATH . 'templates/login-2fa.php';
	}

	/**
	 * Check if current request is a 2FA form submission.
	 *
	 * @return bool
	 */
	public function is_2fa_request() {
		return isset( $_GET['action'] ) && 'wps2fa' === $_GET['action'];
	}
}
