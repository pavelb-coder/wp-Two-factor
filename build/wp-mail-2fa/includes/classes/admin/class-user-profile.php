<?php
/**
 * User profile 2FA section.
 *
 * @package WP_Mail_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Mail_2FA_Admin_User_Profile
 *
 * Adds 2FA management to user profile pages.
 */
class WP_Mail_2FA_Admin_User_Profile {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Mail_2FA_Admin_User_Profile|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Mail_2FA_Admin_User_Profile
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
		add_action( 'show_user_profile', array( $this, 'render_section' ) );
		add_action( 'edit_user_profile', array( $this, 'render_section' ) );
	}

	/**
	 * Render 2FA section on user profile.
	 *
	 * @param WP_User $user User object.
	 */
	public function render_section( $user ) {
		// Only administrators can manage 2FA.
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$helper  = WP_Mail_2FA_User_Helper::get_instance();
		$status  = $helper->get_status( $user->ID );
		$nonce   = wp_create_nonce( 'wpm2fa_nonce' );

		?>
		<h2><?php esc_html_e( 'Двухфакторная аутентификация по email', 'wp-mail-2fa' ); ?></h2>

		<?php if ( $status['enabled'] ) : ?>
			<p class="description"><?php esc_html_e( 'Email 2FA включён.', 'wp-mail-2fa' ); ?></p>
			<p class="description"><?php echo esc_html( sprintf( __( 'Коды подтверждения отправляются на: %s', 'wp-mail-2fa' ), $status['email'] ) ); ?></p>

			<h3><?php esc_html_e( 'Отключить 2FA', 'wp-mail-2fa' ); ?></h3>
			<button type="button" class="button button-danger wpm2fa-disable" data-user-id="<?php echo esc_attr( $user->ID ); ?>" data-nonce="<?php echo esc_attr( $nonce ); ?>">
				<?php esc_html_e( 'Отключить 2FA', 'wp-mail-2fa' ); ?>
			</button>

		<?php else : ?>
			<p class="description"><?php esc_html_e( 'Email 2FA не включён для этого пользователя.', 'wp-mail-2fa' ); ?></p>

			<h3><?php esc_html_e( 'Включить Email 2FA', 'wp-mail-2fa' ); ?></h3>
			<p class="description"><?php esc_html_e( 'При включении код подтверждения будет отправляться на ваш email при каждом входе.', 'wp-mail-2fa' ); ?></p>
			<button type="button" class="button button-primary wpm2fa-enable" data-user-id="<?php echo esc_attr( $user->ID ); ?>" data-nonce="<?php echo esc_attr( $nonce ); ?>">
				<?php esc_html_e( 'Включить 2FA', 'wp-mail-2fa' ); ?>
			</button>
		<?php endif; ?>

		<h3><?php esc_html_e( 'Отправить тестовое email', 'wp-mail-2fa' ); ?></h3>
		<button type="button" class="button wpm2fa-send-test" data-user-id="<?php echo esc_attr( $user->ID ); ?>" data-nonce="<?php echo esc_attr( $nonce ); ?>">
			<?php esc_html_e( 'Отправить тестовый код', 'wp-mail-2fa' ); ?>
		</button>

		<div id="wpm2fa-profile-message" style="display:none;"></div>
		<?php
	}
}
