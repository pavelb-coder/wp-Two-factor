<?php
/**
 * Login 2FA form template.
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Render the 2FA login form.
 *
 * @param int $user_id User ID.
 */
function wps2fa_render_login_2fa_form( $user_id ) {
	$auth    = WP_Secure_2FA_Authentication::get_instance();
	$methods = $auth->get_available_methods( $user_id );

	// Get enabled methods for selection.
	$enabled = array();
	foreach ( $methods as $key => $method ) {
		if ( $method['enabled'] && $method['configured'] ) {
			$enabled[] = array(
				'key'   => $key,
				'label' => $method['label'],
			);
		}
	}

	if ( empty( $enabled ) ) {
		echo '<div class="wps2fa-login-form">';
		echo '<h2>' . esc_html__( 'Two-Factor Authentication', 'wp-secure-2fa' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Please contact your administrator for help setting up 2FA.', 'wp-secure-2fa' ) . '</p>';
		echo '</div>';
		return;
	}

	echo '<div class="wps2fa-login-form">';
	echo '<h2>' . esc_html__( 'Two-Factor Authentication', 'wp-secure-2fa' ) . '</h2>';

	// Show error if any.
	if ( isset( $_GET['error'] ) ) {
		$error_msg = 'invalid_code' === $_GET['error']
			? __( 'Invalid verification code. Please try again.', 'wp-secure-2fa' )
			: __( 'An error occurred. Please try again.', 'wp-secure-2fa' );
		echo '<div class="wps2fa-login-error">' . esc_html( $error_msg ) . '</div>';
	}

	echo '<form method="post" action="' . esc_url( admin_url( 'login-action.php?action=wps2fa' ) ) . '">';
	echo '<input type="hidden" name="_wpnonce" value="' . esc_attr( wp_create_nonce( 'wps2fa_verify' ) ) . '" />';
	echo '<input type="hidden" name="wps2fa_action" value="verify" />';
	echo '<input type="hidden" name="wps2fa_user_id" value="' . esc_attr( $user_id ) . '" />';

	if ( isset( $_GET['redirect_to'] ) ) {
		echo '<input type="hidden" name="wps2fa_redirect" value="' . esc_attr( sanitize_text_field( wp_unslash( $_GET['redirect_to'] ) ) ) . '" />';
	}

	// Method selection (if multiple).
	if ( count( $enabled ) > 1 ) {
		echo '<div class="wps2fa-login-method-select">';
		echo '<label for="wps2fa-method">' . esc_html__( 'Verification method', 'wp-secure-2fa' ) . '</label>';
		echo '<select id="wps2fa-method" name="wps2fa_method">';
		foreach ( $enabled as $method ) {
			echo '<option value="' . esc_attr( $method['key'] ) . '">' . esc_html( $method['label'] ) . '</option>';
		}
		echo '</select>';
		echo '</div>';
	} else {
		echo '<input type="hidden" name="wps2fa_method" value="' . esc_attr( $enabled[0]['key'] ) . '" />';
	}

	echo '<div class="field">';
	echo '<label for="wps2fa-code">' . esc_html__( 'Verification code', 'wp-secure-2fa' ) . '</label>';
	echo '<input type="text" id="wps2fa-code" name="wps2fa_code" placeholder="000000" maxlength="8" autofocus required />';
	echo '</div>';

	echo '<div class="field">';
	echo '<input type="submit" class="button button-primary" value="' . esc_attr__( 'Verify', 'wp-secure-2fa' ) . '" />';
	echo '</div>';

	echo '</form>';

	// Resend email option.
	if ( isset( $methods['email']['enabled'] ) && $methods['email']['enabled'] ) {
		echo '<div class="wps2fa-login-resend">';
		echo '<a href="' . esc_url( add_query_arg( 'wps2fa_resend_email', $user_id ) ) . '">' . esc_html__( 'Resend email code', 'wp-secure-2fa' ) . '</a>';
		echo '</div>';
	}

	// Back to login.
	echo '<div class="wps2fa-login-back">';
	echo '<a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Back to login', 'wp-secure-2fa' ) . '</a>';
	echo '</div>';

	echo '</div>';
}
