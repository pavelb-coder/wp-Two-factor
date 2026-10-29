<?php
/**
 * REST API endpoints for 2FA.
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Secure_2FA_REST_API
 *
 * Provides REST API endpoints for 2FA operations.
 */
class WP_Secure_2FA_REST_API {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Secure_2FA_REST_API|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Secure_2FA_REST_API
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
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Register REST routes.
	 */
	public function register_routes() {
		register_rest_route(
			'wps2fa/v1',
			'/generate-totp',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'generate_totp' ),
				'permission_callback' => array( $this, 'check_auth' ),
			)
		);

		register_rest_route(
			'wps2fa/v1',
			'/verify-totp',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'verify_totp' ),
				'permission_callback' => array( $this, 'check_auth' ),
			)
		);

		register_rest_route(
			'wps2fa/v1',
			'/validate',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'validate_code' ),
				'permission_callback' => array( $this, 'check_auth' ),
			)
		);

		register_rest_route(
			'wps2fa/v1',
			'/methods',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_methods' ),
				'permission_callback' => array( $this, 'check_auth' ),
			)
		);

		register_rest_route(
			'wps2fa/v1',
			'/status',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_status' ),
				'permission_callback' => array( $this, 'check_auth' ),
			)
		);

		register_rest_route(
			'wps2fa/v1',
			'/backup-codes',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'generate_backup_codes' ),
				'permission_callback' => array( $this, 'check_auth' ),
			)
		);

		register_rest_route(
			'wps2fa/v1',
			'/settings',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => array( $this, 'update_settings' ),
				'permission_callback' => array( $this, 'check_admin_auth' ),
			)
		);
	}

	/**
	 * Check authentication.
	 *
	 * @return bool|WP_Error
	 */
	public function check_auth() {
		if ( ! is_user_logged_in() ) {
			return new WP_Error( 'wps2fa_not_authenticated', __( 'Not authenticated.', 'wp-secure-2fa' ), array( 'status' => 401 ) );
		}
		return true;
	}

	/**
	 * Check admin authentication.
	 *
	 * @return bool|WP_Error
	 */
	public function check_admin_auth() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error( 'wps2fa_not_authorized', __( 'Not authorized.', 'wp-secure-2fa' ), array( 'status' => 403 ) );
		}
		return true;
	}

	/**
	 * Generate TOTP secret.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public function generate_totp( $request ) {
		$user_id = get_current_user_id();
		$totp    = WP_Secure_2FA_TOTP::get_instance();
		$secret  = $totp->generate_secret();

		$_SESSION['wps2fa_new_secret'] = $secret;

		$authcode_url = $totp->get_authcode_url(
			WP_Secure_2FA_Settings::get_instance()->get( 'totp_issuer', 'WP Secure 2FA' ),
			get_userdata( $user_id )->user_login
		);

		return rest_ensure_response(
			array(
				'secret'       => $secret,
				'authcode_url' => $authcode_url,
			)
		);
	}

	/**
	 * Verify TOTP code.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public function verify_totp( $request ) {
		$user_id = get_current_user_id();
		$code    = $request->get_param( 'code' );

		if ( empty( $code ) || empty( $_SESSION['wps2fa_new_secret'] ) ) {
			return new WP_Error( 'wps2fa_invalid_request', __( 'Invalid request.', 'wp-secure-2fa' ), array( 'status' => 400 ) );
		}

		$totp   = WP_Secure_2FA_TOTP::get_instance();
		$secret = $_SESSION['wps2fa_new_secret'];

		if ( ! $totp->verify( $code, $secret ) ) {
			return new WP_Error( 'wps2fa_invalid_code', __( 'Invalid code.', 'wp-secure-2fa' ), array( 'status' => 400 ) );
		}

		WP_Secure_2FA_User_Helper::get_instance()->set_totp_secret( $user_id, $secret );
		WP_Secure_2FA_User_Helper::get_instance()->enable_method( $user_id, 'totp' );

		unset( $_SESSION['wps2fa_new_secret'] );

		return rest_ensure_response( array( 'message' => __( 'TOTP configured.', 'wp-secure-2fa' ) ) );
	}

	/**
	 * Validate a 2FA code.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public function validate_code( $request ) {
		$user_id = isset( $request['user_id'] ) ? absint( $request['user_id'] ) : get_current_user_id();
		$code    = $request->get_param( 'code' );
		$method  = $request->get_param( 'method' );

		if ( empty( $code ) ) {
			return new WP_Error( 'wps2fa_invalid_request', __( 'Invalid request.', 'wp-secure-2fa' ), array( 'status' => 400 ) );
		}

		$auth   = WP_Secure_2FA_Authentication::get_instance();
		$result = $auth->validate( $user_id, $code, $method );

		if ( $result['success'] ) {
			return rest_ensure_response( array( 'valid' => true, 'method' => $result['method'] ) );
		}

		return new WP_Error( 'wps2fa_invalid_code', __( 'Invalid code.', 'wp-secure-2fa' ), array( 'status' => 400 ) );
	}

	/**
	 * Get available methods for current user.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public function get_methods( $request ) {
		$user_id = get_current_user_id();
		$auth    = WP_Secure_2FA_Authentication::get_instance();

		return rest_ensure_response( array( 'methods' => $auth->get_available_methods( $user_id ) ) );
	}

	/**
	 * Get 2FA status for current user.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public function get_status( $request ) {
		$user_id = get_current_user_id();
		$helper  = WP_Secure_2FA_User_Helper::get_instance();

		return rest_ensure_response( $helper->get_status( $user_id ) );
	}

	/**
	 * Generate backup codes.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public function generate_backup_codes( $request ) {
		$user_id = get_current_user_id();
		$backup  = WP_Secure_2FA_Backup_Codes::get_instance();
		$codes   = $backup->generate_for_user( $user_id );

		if ( false === $codes ) {
			return new WP_Error( 'wps2fa_failed', __( 'Failed to generate backup codes.', 'wp-secure-2fa' ), array( 'status' => 500 ) );
		}

		WP_Secure_2FA_User_Helper::get_instance()->enable_method( $user_id, 'backup_codes' );

		return rest_ensure_response( array( 'codes' => $codes ) );
	}

	/**
	 * Update settings (admin only).
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public function update_settings( $request ) {
		$settings = $request->get_param( 'settings' );

		if ( empty( $settings ) ) {
			return new WP_Error( 'wps2fa_invalid_request', __( 'Invalid request.', 'wp-secure-2fa' ), array( 'status' => 400 ) );
		}

		$sanitized = WP_Secure_2FA_Settings::get_instance()->sanitize( $settings );

		if ( WP_Secure_2FA_Settings::get_instance()->save( $sanitized ) ) {
			return rest_ensure_response( array( 'message' => __( 'Settings saved.', 'wp-secure-2fa' ) ) );
		}

		return new WP_Error( 'wps2fa_failed', __( 'Failed to save settings.', 'wp-secure-2fa' ), array( 'status' => 500 ) );
	}
}
