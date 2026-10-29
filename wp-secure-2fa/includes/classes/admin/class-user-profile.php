<?php
/**
 * User profile 2FA section.
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Secure_2FA_Admin_User_Profile
 *
 * Adds 2FA management to user profile pages.
 */
class WP_Secure_2FA_Admin_User_Profile {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Secure_2FA_Admin_User_Profile|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Secure_2FA_Admin_User_Profile
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
		add_action( 'personal_options_update', array( $this, 'save_section' ) );
		add_action( 'edit_user_profile_update', array( $this, 'save_section' ) );
	}

	/**
	 * Render 2FA section on user profile.
	 *
	 * @param WP_User $user User object.
	 */
	public function render_section( $user ) {
		$helper  = WP_Secure_2FA_User_Helper::get_instance();
		$status  = $helper->get_status( $user->ID );
		$auth    = WP_Secure_2FA_Authentication::get_instance();
		$methods = $auth->get_available_methods( $user->ID );
		$nonce   = wp_create_nonce( 'wps2fa_nonce' );

		?>
		<h2><?php esc_html_e( 'Two-Factor Authentication', 'wp-secure-2fa' ); ?></h2>

		<?php if ( $status['enabled'] && $status['configured'] ) : ?>
			<p class="description"><?php esc_html_e( '2FA is enabled and configured.', 'wp-secure-2fa' ); ?></p>

			<h3><?php esc_html_e( 'Enabled Methods', 'wp-secure-2fa' ); ?></h3>
			<ul>
				<?php foreach ( $methods as $key => $method ) : ?>
					<?php if ( $method['enabled'] ) : ?>
						<li><?php echo esc_html( $method['label'] ); ?></li>
					<?php endif; ?>
				<?php endforeach; ?>
			</ul>

			<?php if ( $status['backup_count'] > 0 ) : ?>
				<p class="description"><?php echo esc_html( sprintf( _n( '%s backup code remaining.', '%s backup codes remaining.', $status['backup_count'], 'wp-secure-2fa' ), $status['backup_count'] ) ); ?></p>
			<?php endif; ?>

			<h3><?php esc_html_e( 'Regenerate Backup Codes', 'wp-secure-2fa' ); ?></h3>
			<button type="button" class="button wps2fa-regenerate-backup" data-user-id="<?php echo esc_attr( $user->ID ); ?>" data-nonce="<?php echo esc_attr( $nonce ); ?>">
				<?php esc_html_e( 'Regenerate', 'wp-secure-2fa' ); ?>
			</button>

			<h3><?php esc_html_e( 'Disable 2FA', 'wp-secure-2fa' ); ?></h3>
			<button type="button" class="button button-danger wps2fa-disable" data-user-id="<?php echo esc_attr( $user->ID ); ?>" data-nonce="<?php echo esc_attr( $nonce ); ?>">
				<?php esc_html_e( 'Disable 2FA', 'wp-secure-2fa' ); ?>
			</button>

		<?php else : ?>
			<p class="description"><?php esc_html_e( '2FA is not enabled for this user.', 'wp-secure-2fa' ); ?></p>

			<h3><?php esc_html_e( 'Set Up TOTP', 'wp-secure-2fa' ); ?></h3>
			<button type="button" class="button wps2fa-setup-totp" data-user-id="<?php echo esc_attr( $user->ID ); ?>" data-nonce="<?php echo esc_attr( $nonce ); ?>">
				<?php esc_html_e( 'Set up authenticator app', 'wp-secure-2fa' ); ?>
			</button>

			<h3><?php esc_html_e( 'Set Up Backup Codes', 'wp-secure-2fa' ); ?></h3>
			<button type="button" class="button wps2fa-generate-backup" data-user-id="<?php echo esc_attr( $user->ID ); ?>" data-nonce="<?php echo esc_attr( $nonce ); ?>">
				<?php esc_html_e( 'Generate backup codes', 'wp-secure-2fa' ); ?>
			</button>

			<h3><?php esc_html_e( 'Set Up Email', 'wp-secure-2fa' ); ?></h3>
			<button type="button" class="button wps2fa-setup-email" data-user-id="<?php echo esc_attr( $user->ID ); ?>" data-nonce="<?php echo esc_attr( $nonce ); ?>">
				<?php esc_html_e( 'Enable email verification', 'wp-secure-2fa' ); ?>
			</button>

		<?php endif; ?>

		<div id="wps2fa-setup-container"></div>
		<div id="wps2fa-backup-container" style="display:none;">
			<p><?php esc_html_e( 'Save these backup codes. Each code can only be used once.', 'wp-secure-2fa' ); ?></p>
			<textarea id="wps2fa-backup-codes" readonly rows="10" cols="50"></textarea>
		</div>
		<?php
	}

	/**
	 * Save user profile section (placeholder for future use).
	 *
	 * @param int $user_id User ID.
	 */
	public function save_section( $user_id ) {
		// Most 2FA actions are handled via AJAX.
	}
}
