<?php
/**
 * Setup wizard for initial 2FA configuration.
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Secure_2FA_Admin_Setup_Wizard
 *
 * Guides admin through initial plugin setup.
 */
class WP_Secure_2FA_Admin_Setup_Wizard {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Secure_2FA_Admin_Setup_Wizard|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Secure_2FA_Admin_Setup_Wizard
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
		add_action( 'admin_menu', array( $this, 'register_wizard_page' ) );
		add_action( 'admin_init', array( $this, 'handle_wizard' ) );
	}

	/**
	 * Register wizard page.
	 */
	public function register_wizard_page() {
		if ( ! get_transient( 'wps2fa_setup_wizard' ) ) {
			return;
		}

		add_dashboard_page(
			__( 'WP Secure 2FA Setup', 'wp-secure-2fa' ),
			__( 'WP Secure 2FA Setup', 'wp-secure-2fa' ),
			'manage_options',
			'wps2fa-wizard',
			array( $this, 'render_wizard' )
		);
	}

	/**
	 * Handle wizard actions.
	 */
	public function handle_wizard() {
		if ( ! isset( $_GET['page'] ) || 'wps2fa-wizard' !== $_GET['page'] ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// Skip wizard action.
		if ( isset( $_GET['wps2fa_skip'] ) ) {
			delete_transient( 'wps2fa_setup_wizard' );
			wp_safe_redirect( admin_url( 'options-general.php?page=wps2fa-settings' ) );
			exit;
		}

		// Complete wizard.
		if ( isset( $_GET['wps2fa_complete'] ) ) {
			delete_transient( 'wps2fa_setup_wizard' );
			wp_safe_redirect( admin_url( 'options-general.php?page=wps2fa-settings' ) );
			exit;
		}
	}

	/**
	 * Render wizard.
	 */
	public function render_wizard() {
		$settings = WP_Secure_2FA_Settings::get_instance();

		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'WP Secure 2FA — Quick Setup', 'wp-secure-2fa' ); ?></h1>

			<div class="wps2fa-wizard-card">
				<h2><?php esc_html_e( 'Welcome!', 'wp-secure-2fa' ); ?></h2>
				<p><?php esc_html_e( 'Let\'s set up two-factor authentication on your site. This quick wizard will configure the basics.', 'wp-secure-2fa' ); ?></p>

				<div class="wps2fa-wizard-steps">
					<div class="wps2fa-step">
						<h3><?php esc_html_e( 'Step 1: Choose Methods', 'wp-secure-2fa' ); ?></h3>
						<p><?php esc_html_e( 'TOTP and backup codes are recommended.', 'wp-secure-2fa' ); ?></p>
					</div>

					<div class="wps2fa-step">
						<h3><?php esc_html_e( 'Step 2: Configure', 'wp-secure-2fa' ); ?></h3>
						<p><?php esc_html_e( 'Set issuer name and enforcement options.', 'wp-secure-2fa' ); ?></p>
					</div>

					<div class="wps2fa-step">
						<h3><?php esc_html_e( 'Step 3: You\'re Done!', 'wp-secure-2fa' ); ?></h3>
						<p><?php esc_html_e( '2FA is ready. Users can set up their authenticator apps.', 'wp-secure-2fa' ); ?></p>
					</div>
				</div>

				<div class="wps2fa-wizard-actions">
					<a href="<?php echo esc_url( admin_url( 'options-general.php?page=wps2fa-settings' ) ); ?>" class="button button-primary">
						<?php esc_html_e( 'Go to Settings', 'wp-secure-2fa' ); ?>
					</a>
					<a href="<?php echo esc_url( add_query_arg( 'wps2fa_skip', '1' ) ); ?>" class="button">
						<?php esc_html_e( 'Skip for Now', 'wp-secure-2fa' ); ?>
					</a>
				</div>
			</div>
		</div>
		<?php
	}
}
