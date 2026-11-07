<?php
/**
 * REST API endpoints for 2FA.
 *
 * @package WP_Mail_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Mail_2FA_REST_API
 *
 * Provides REST API endpoints for 2FA operations.
 */
class WP_Mail_2FA_REST_API {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Mail_2FA_REST_API|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Mail_2FA_REST_API
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
			'wpm2fa/v1',
			'/send-code',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'send_code' ),
				'permission_callback' => array( $this, 'check_auth' ),
			)
		);

		register_rest_route(
			'wpm2fa/v1',
			'/validate',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'validate_code' ),
				'permission_callback' => array( $this, 'check_auth' ),
			)
		);

		register_rest_route(
			'wpm2fa/v1',
			'/methods',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_methods' ),
				'permission_callback' => array( $this, 'check_auth' ),
			)
		);

		register_rest_route(
			'wpm2fa/v1',
			'/status',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'get_status' ),
				'permission_callback' => array( $this, 'check_auth' ),
			)
		);

		register_rest_route(
			'wpm2fa/v1',
			'/disable',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'disable_2fa' ),
				'permission_callback' => array( $this, 'check_auth' ),
			)
		);

		register_rest_route(
			'wpm2fa/v1',
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
			return new WP_Error( 'wpm2fa_not_authenticated', __( 'Not authenticated.', 'wp-mail-2fa' ), array( 'status' => 401 ) );
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
			return new WP_Error( 'wpm2fa_not_authorized', __( 'Not authorized.', 'wp-mail-2fa' ), array( 'status' => 403 ) );
		}
		return true;
	}

	/**
	 * Send email code.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public function send_code( $request ) {
		$user_id = isset( $request['user_id'] ) ? absint( $request['user_id'] ) : get_current_user_id();

		if ( ! $user_id ) {
			return new WP_Error( 'wpm2fa_invalid_request', __( 'Invalid request.', 'wp-mail-2fa' ), array( 'status' => 400 ) );
		}

		$email   = WP_Mail_2FA_Email::get_instance();
		$result  = $email->send_code( $user_id, 'login' );

		if ( false === $result ) {
			return new WP_Error( 'wpm2fa_failed', __( 'Failed to send email.', 'wp-mail-2fa' ), array( 'status' => 500 ) );
		}

		return rest_ensure_response( array( 'message' => __( 'Verification code sent.', 'wp-mail-2fa' ) ) );
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

		if ( empty( $code ) ) {
			return new WP_Error( 'wpm2fa_invalid_request', __( 'Invalid request.', 'wp-mail-2fa' ), array( 'status' => 400 ) );
		}

		$auth   = WP_Mail_2FA_Authentication::get_instance();
		$result = $auth->validate( $user_id, $code );

		if ( $result['success'] ) {
			return rest_ensure_response( array( 'valid' => true, 'method' => $result['method'] ) );
		}

		return new WP_Error( 'wpm2fa_invalid_code', __( 'Invalid code.', 'wp-mail-2fa' ), array( 'status' => 400 ) );
	}

	/**
	 * Get available methods for current user.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public function get_methods( $request ) {
		$user_id = get_current_user_id();
		$auth    = WP_Mail_2FA_Authentication::get_instance();

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
		$helper  = WP_Mail_2FA_User_Helper::get_instance();

		return rest_ensure_response( $helper->get_status( $user_id ) );
	}

	/**
	 * Disable 2FA for a user.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public function disable_2fa( $request ) {
		$user_id = isset( $request['user_id'] ) ? absint( $request['user_id'] ) : get_current_user_id();

		if ( ! $user_id ) {
			return new WP_Error( 'wpm2fa_invalid_request', __( 'Invalid request.', 'wp-mail-2fa' ), array( 'status' => 400 ) );
		}

		WP_Mail_2FA_User_Helper::get_instance()->disable( $user_id );

		return rest_ensure_response( array( 'message' => __( '2FA disabled.', 'wp-mail-2fa' ) ) );
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
			return new WP_Error( 'wpm2fa_invalid_request', __( 'Invalid request.', 'wp-mail-2fa' ), array( 'status' => 400 ) );
		}

		$sanitized = WP_Mail_2FA_Settings::get_instance()->sanitize( $settings );

		if ( WP_Mail_2FA_Settings::get_instance()->save( $sanitized ) ) {
			return rest_ensure_response( array( 'message' => __( 'Settings saved.', 'wp-mail-2fa' ) ) );
		}

		return new WP_Error( 'wpm2fa_failed', __( 'Failed to save settings.', 'wp-mail-2fa' ), array( 'status' => 500 ) );
	}
}
