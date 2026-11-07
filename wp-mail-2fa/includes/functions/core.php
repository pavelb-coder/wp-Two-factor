<?php
/**
 * Core plugin functions.
 *
 * @package WP_Mail_2FA
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
function wpm2fa_user_needs_2fa( $user_id ) {
	return WP_Mail_2FA_Authentication::get_instance()->needs_2fa( $user_id );
}

/**
 * Get user's 2FA status.
 *
 * @param int $user_id User ID.
 * @return array
 */
function wpm2fa_get_user_status( $user_id ) {
	return WP_Mail_2FA_User_Helper::get_instance()->get_status( $user_id );
}

/**
 * Get plugin settings.
 *
 * @param string $key     Setting key.
 * @param mixed  $default Default value.
 * @return mixed
 */
function wpm2fa_get_setting( $key, $default = null ) {
	return WP_Mail_2FA_Settings::get_instance()->get( $key, $default );
}

/**
 * Save plugin settings.
 *
 * @param array $settings Settings array.
 * @return bool
 */
function wpm2fa_save_settings( $settings ) {
	$sanitized = WP_Mail_2FA_Settings::get_instance()->sanitize( $settings );
	return WP_Mail_2FA_Settings::get_instance()->save( $sanitized );
}

/**
 * Send email 2FA code.
 *
 * @param int $user_id User ID.
 * @return string|false Code or false.
 */
function wpm2fa_send_email_code( $user_id ) {
	return WP_Mail_2FA_Email::get_instance()->send_code( $user_id, 'login' );
}

/**
 * Validate a 2FA code for a user.
 *
 * @param int    $user_id User ID.
 * @param string $code    Code to validate.
 * @return bool True on success.
 */
function wpm2fa_validate_code( $user_id, $code ) {
	$result = WP_Mail_2FA_Authentication::get_instance()->validate( $user_id, $code );
	return $result['success'];
}

/**
 * Enable 2FA for a user.
 *
 * @param int $user_id User ID.
 */
function wpm2fa_enable_user_2fa( $user_id ) {
	WP_Mail_2FA_User_Helper::get_instance()->enable( $user_id );
}

/**
 * Disable 2FA for a user.
 *
 * @param int $user_id User ID.
 */
function wpm2fa_disable_user_2fa( $user_id ) {
	WP_Mail_2FA_User_Helper::get_instance()->disable( $user_id );
}

/**
 * Check if a user is in grace period.
 *
 * @param int $user_id User ID.
 * @return bool
 */
function wpm2fa_in_grace_period( $user_id ) {
	return WP_Mail_2FA_Grace_Period::get_instance()->is_in_grace( $user_id );
}

/**
 * Get grace period deadline.
 *
 * @param int $user_id User ID.
 * @return int|false
 */
function wpm2fa_get_grace_deadline( $user_id ) {
	return WP_Mail_2FA_Grace_Period::get_instance()->get_deadline( $user_id );
}

/**
 * Render the 2FA login form.
 *
 * @param int $user_id User ID.
 */
function wpm2fa_render_login_2fa_form( $user_id ) {
	include WP_MAIL_2FA_PATH . 'templates/login-2fa.php';
}
