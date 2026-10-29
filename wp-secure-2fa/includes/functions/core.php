<?php
/**
 * Core plugin functions.
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Check if current user needs 2FA on login.
 *
 * @param int $user_id User ID.
 * @return bool
 */
function wps2fa_user_needs_2fa( $user_id ) {
	return WP_Secure_2FA_Authentication::get_instance()->needs_2fa( $user_id );
}

/**
 * Get user's 2FA status.
 *
 * @param int $user_id User ID.
 * @return array
 */
function wps2fa_get_user_status( $user_id ) {
	return WP_Secure_2FA_User_Helper::get_instance()->get_status( $user_id );
}

/**
 * Get plugin settings.
 *
 * @param string $key     Setting key.
 * @param mixed  $default Default value.
 * @return mixed
 */
function wps2fa_get_setting( $key, $default = null ) {
	return WP_Secure_2FA_Settings::get_instance()->get( $key, $default );
}

/**
 * Save plugin settings.
 *
 * @param array $settings Settings array.
 * @return bool
 */
function wps2fa_save_settings( $settings ) {
	$sanitized = WP_Secure_2FA_Settings::get_instance()->sanitize( $settings );
	return WP_Secure_2FA_Settings::get_instance()->save( $sanitized );
}

/**
 * Get enabled 2FA methods for a user.
 *
 * @param int $user_id User ID.
 * @return array
 */
function wps2fa_get_user_methods( $user_id ) {
	return WP_Secure_2FA_Authentication::get_instance()->get_available_methods( $user_id );
}

/**
 * Generate a new TOTP secret for a user.
 *
 * @param int $user_id User ID.
 * @return string|false Secret or false on failure.
 */
function wps2fa_generate_totp_secret( $user_id ) {
	$totp   = WP_Secure_2FA_TOTP::get_instance();
	$secret = $totp->generate_secret();

	$_SESSION['wps2fa_new_secret'] = $secret;

	return $secret;
}

/**
 * Verify and save TOTP secret for a user.
 *
 * @param int    $user_id User ID.
 * @param string $code    TOTP code.
 * @return bool True on success.
 */
function wps2fa_verify_and_save_totp( $user_id, $code ) {
	if ( empty( $_SESSION['wps2fa_new_secret'] ) ) {
		return false;
	}

	$totp   = WP_Secure_2FA_TOTP::get_instance();
	$secret = $_SESSION['wps2fa_new_secret'];

	if ( ! $totp->verify( $code, $secret ) ) {
		return false;
	}

	WP_Secure_2FA_User_Helper::get_instance()->set_totp_secret( $user_id, $secret );
	WP_Secure_2FA_User_Helper::get_instance()->enable_method( $user_id, 'totp' );

	unset( $_SESSION['wps2fa_new_secret'] );

	return true;
}

/**
 * Generate backup codes for a user.
 *
 * @param int $user_id User ID.
 * @return array|false Array of codes or false.
 */
function wps2fa_generate_backup_codes( $user_id ) {
	$backup = WP_Secure_2FA_Backup_Codes::get_instance();
	$codes  = $backup->generate_for_user( $user_id );

	WP_Secure_2FA_User_Helper::get_instance()->enable_method( $user_id, 'backup_codes' );

	return $codes;
}

/**
 * Send email 2FA code.
 *
 * @param int $user_id User ID.
 * @return string|false Code or false.
 */
function wps2fa_send_email_code( $user_id ) {
	return WP_Secure_2FA_Email::get_instance()->send_code( $user_id, 'login' );
}

/**
 * Validate a 2FA code for a user.
 *
 * @param int    $user_id User ID.
 * @param string $code    Code to validate.
 * @param string $method  Specific method (optional).
 * @return bool True on success.
 */
function wps2fa_validate_code( $user_id, $code, $method = '' ) {
	$result = WP_Secure_2FA_Authentication::get_instance()->validate( $user_id, $code, $method );
	return $result['success'];
}

/**
 * Disable 2FA for a user.
 *
 * @param int $user_id User ID.
 */
function wps2fa_disable_user_2fa( $user_id ) {
	WP_Secure_2FA_User_Helper::get_instance()->set_enabled_methods( $user_id, array() );
	WP_Secure_2FA_User_Helper::get_instance()->delete_totp_secret( $user_id );
	WP_Secure_2FA_Backup_Codes::get_instance()->delete_for_user( $user_id );
	delete_user_meta( $user_id, 'wps2fa_email_code' );
	delete_user_meta( $user_id, 'wps2fa_email_code_expiry' );
}

/**
 * Check if a user is in grace period.
 *
 * @param int $user_id User ID.
 * @return bool
 */
function wps2fa_in_grace_period( $user_id ) {
	return WP_Secure_2FA_Grace_Period::get_instance()->is_in_grace( $user_id );
}

/**
 * Get grace period deadline.
 *
 * @param int $user_id User ID.
 * @return int|false
 */
function wps2fa_get_grace_deadline( $user_id ) {
	return WP_Secure_2FA_Grace_Period::get_instance()->get_deadline( $user_id );
}

/**
 * Get backup codes remaining for a user.
 *
 * @param int $user_id User ID.
 * @return int
 */
function wps2fa_get_backup_count( $user_id ) {
	return WP_Secure_2FA_Backup_Codes::get_instance()->get_remaining_count( $user_id );
}

/**
 * Get TOTP authcode URL for a user.
 *
 * @param int $user_id User ID.
 * @return string
 */
function wps2fa_get_totp_authcode_url( $user_id ) {
	$secret = WP_Secure_2FA_User_Helper::get_instance()->get_totp_secret( $user_id );
	if ( empty( $secret ) ) {
		return '';
	}

	$totp = WP_Secure_2FA_TOTP::get_instance();
	$user = get_userdata( $user_id );

	return $totp->get_authcode_url(
		wps2fa_get_setting( 'totp_issuer', 'WP Secure 2FA' ),
		$user ? $user->user_login : ''
	);
}

/**
 * Register REST API routes (called from main class).
 */
function wps2fa_rest_api_init() {
	WP_Secure_2FA_REST_API::get_instance();
}
