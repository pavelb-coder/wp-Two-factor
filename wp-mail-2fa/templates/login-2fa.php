<?php
/**
 * Login 2FA form template.
 *
 * This template is included by wpm2fa_render_login_2fa_form() in core.php.
 * It expects $user_id to be available.
 *
 * @package WP_Mail_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$user       = get_userdata( $user_id );
$email      = $user ? $user->user_email : '';
$settings   = WP_Mail_2FA_Settings::get_instance();
$code_length = (int) $settings->get( 'code_length', 6 );

// Check if email already sent.
$email_instance = WP_Mail_2FA_Email::get_instance();
$has_code = $email_instance->has_valid_code( $user_id );

echo '<div class="wpm2fa-login-form">';
echo '<h2>' . esc_html__( 'Подтверждение по email', 'wp-mail-2fa' ) . '</h2>';

// Show info message.
echo '<div class="wpm2fa-login-info">';
echo esc_html( sprintf( __( 'Код подтверждения отправлен на %s', 'wp-mail-2fa' ), $email ) );
echo '</div>';

// Show error if any.
if ( isset( $_GET['error'] ) ) {
	$error_msg = 'invalid_code' === $_GET['error']
		? __( 'Неверный код подтверждения. Попробуйте снова.', 'wp-mail-2fa' )
		: __( 'Произошла ошибка. Попробуйте снова.', 'wp-mail-2fa' );
	echo '<div class="wpm2fa-login-error">' . esc_html( $error_msg ) . '</div>';
}

echo '<form method="post" action="' . esc_url( admin_url( 'login-action.php?action=wpm2fa' ) ) . '">';
echo '<input type="hidden" name="_wpnonce" value="' . esc_attr( wp_create_nonce( 'wpm2fa_verify' ) ) . '" />';
echo '<input type="hidden" name="wpm2fa_action" value="verify" />';
echo '<input type="hidden" name="wpm2fa_user_id" value="' . esc_attr( $user_id ) . '" />';

if ( isset( $_GET['redirect_to'] ) ) {
	echo '<input type="hidden" name="wpm2fa_redirect" value="' . esc_attr( sanitize_text_field( wp_unslash( $_GET['redirect_to'] ) ) ) . '" />';
}

echo '<div class="field">';
echo '<label for="wpm2fa-code">' . esc_html__( 'Код подтверждения', 'wp-mail-2fa' ) . '</label>';
echo '<input type="text" id="wpm2fa-code" name="wpm2fa_code" placeholder="' . esc_attr( str_repeat( '0', $code_length ) ) . '" maxlength="' . esc_attr( $code_length ) . '" autofocus required />';
echo '</div>';

echo '<div class="field">';
echo '<input type="submit" class="button button-primary" value="' . esc_attr__( 'Подтвердить', 'wp-mail-2fa' ) . '" />';
echo '</div>';

echo '</form>';

// Resend email option.
if ( $has_code ) {
	echo '<div class="wpm2fa-login-resend">';
	echo '<a href="' . esc_url( add_query_arg( 'wpm2fa_resend_email', $user_id ) ) . '">' . esc_html__( 'Переотправить код', 'wp-mail-2fa' ) . '</a>';
	echo '</div>';
} else {
	echo '<div class="wpm2fa-login-resend">';
	echo '<a href="' . esc_url( add_query_arg( 'wpm2fa_send_email', $user_id ) ) . '">' . esc_html__( "Не получили код? Отправить снова", 'wp-mail-2fa' ) . '</a>';
	echo '</div>';
}

// Back to login.
echo '<div class="wpm2fa-login-back">';
echo '<a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Вернуться к входу', 'wp-mail-2fa' ) . '</a>';
echo '</div>';

echo '</div>';
