<?php
/**
 * Admin settings page.
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Secure_2FA_Admin_Settings_Page
 *
 * Registers and renders the plugin settings page.
 */
class WP_Secure_2FA_Admin_Settings_Page {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Secure_2FA_Admin_Settings_Page|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Secure_2FA_Admin_Settings_Page
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
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_init', array( $this, 'handle_save' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( WP_SECURE_2FA_PATH . 'wp-secure-2fa.php' ), array( $this, 'add_action_link' ) );
	}

	/**
	 * Register admin menu.
	 */
	public function register_menu() {
		add_options_page(
			__( 'WP Secure 2FA Settings', 'wp-secure-2fa' ),
			__( 'WP Secure 2FA', 'wp-secure-2fa' ),
			'manage_options',
			'wps2fa-settings',
			array( $this, 'render_page' )
		);
	}

	/**
	 * Add settings link to plugin row.
	 *
	 * @param array $links Existing links.
	 * @return array
	 */
	public function add_action_link( $links ) {
		$settings_link = '<a href="' . esc_url( admin_url( 'options-general.php?page=wps2fa-settings' ) ) . '">' . esc_html__( 'Settings', 'wp-secure-2fa' ) . '</a>';
		array_unshift( $links, $settings_link );
		return $links;
	}

	/**
	 * Handle settings save.
	 */
	public function handle_save() {
		if ( ! isset( $_POST['wps2fa_settings'] ) ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], 'wps2fa_settings' ) ) {
			return;
		}

		$settings = $_POST['wps2fa_settings'];
		$sanitized = WP_Secure_2FA_Settings::get_instance()->sanitize( $settings );

		WP_Secure_2FA_Settings::get_instance()->save( $sanitized );

		add_action( 'admin_notices', array( $this, 'show_saved_notice' ) );
	}

	/**
	 * Show settings saved notice.
	 */
	public function show_saved_notice() {
		echo '<div class="notice notice-success"><p>' . esc_html__( 'Settings saved successfully.', 'wp-secure-2fa' ) . '</p></div>';
	}

	/**
	 * Render settings page.
	 */
	public function render_page() {
		$settings = WP_Secure_2FA_Settings::get_instance();
		$all      = $settings->get_all();
		$roles    = get_editable_roles();

		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'WP Secure 2FA Settings', 'wp-secure-2fa' ); ?></h1>

			<form method="post" action="">
				<?php wp_nonce_field( 'wps2fa_settings' ); ?>

				<h2 class="title"><?php esc_html_e( 'Authentication Methods', 'wp-secure-2fa' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Authenticator app (TOTP)', 'wp-secure-2fa' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="wps2fa_settings[enable_totp]" value="1" <?php checked( $all['enable_totp'], 'yes' ); ?> />
								<?php esc_html_e( 'Enable TOTP', 'wp-secure-2fa' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Backup codes', 'wp-secure-2fa' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="wps2fa_settings[enable_backup_codes]" value="1" <?php checked( $all['enable_backup_codes'], 'yes' ); ?> />
								<?php esc_html_e( 'Enable backup codes', 'wp-secure-2fa' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Email verification', 'wp-secure-2fa' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="wps2fa_settings[enable_email]" value="1" <?php checked( $all['enable_email'], 'yes' ); ?> />
								<?php esc_html_e( 'Enable email verification', 'wp-secure-2fa' ); ?>
							</label>
						</td>
					</tr>
				</table>

				<h2 class="title"><?php esc_html_e( 'TOTP Settings', 'wp-secure-2fa' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><label for="totp_issuer"><?php esc_html_e( 'Issuer name', 'wp-secure-2fa' ); ?></label></th>
						<td>
							<input type="text" id="totp_issuer" name="wps2fa_settings[totp_issuer]" value="<?php echo esc_attr( $all['totp_issuer'] ); ?>" class="regular-text" />
							<p class="description"><?php esc_html_e( 'Name shown in authenticator apps.', 'wp-secure-2fa' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="totp_period"><?php esc_html_e( 'Time period (seconds)', 'wp-secure-2fa' ); ?></label></th>
						<td>
							<input type="number" id="totp_period" name="wps2fa_settings[totp_period]" value="<?php echo esc_attr( $all['totp_period'] ); ?>" min="10" max="300" />
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="totp_digits"><?php esc_html_e( 'Digits', 'wp-secure-2fa' ); ?></label></th>
						<td>
							<select id="totp_digits" name="wps2fa_settings[totp_digits]">
								<?php for ( $d = 6; $d <= 8; $d++ ) : ?>
									<option value="<?php echo esc_attr( $d ); ?>" <?php selected( $all['totp_digits'], $d ); ?>><?php echo esc_html( $d ); ?></option>
								<?php endfor; ?>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="totp_algorithm"><?php esc_html_e( 'Hash algorithm', 'wp-secure-2fa' ); ?></label></th>
						<td>
							<select id="totp_algorithm" name="wps2fa_settings[totp_algorithm]">
								<?php foreach ( array( 'sha1', 'sha256', 'sha512' ) as $algo ) : ?>
									<option value="<?php echo esc_attr( $algo ); ?>" <?php selected( $all['totp_algorithm'], $algo ); ?>><?php echo esc_html( strtoupper( $algo ) ); ?></option>
								<?php endforeach; ?>
							</select>
						</td>
					</tr>
				</table>

				<h2 class="title"><?php esc_html_e( 'Enforcement', 'wp-secure-2fa' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Require 2FA', 'wp-secure-2fa' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="wps2fa_settings[enforce_2fa]" value="1" <?php checked( $all['enforce_2fa'], 'yes' ); ?> />
								<?php esc_html_e( 'Require 2FA for all users', 'wp-secure-2fa' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Grace period', 'wp-secure-2fa' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="wps2fa_settings[grace_period_enabled]" value="1" <?php checked( $all['grace_period_enabled'], 'yes' ); ?> />
								<?php esc_html_e( 'Enable grace period', 'wp-secure-2fa' ); ?>
							</label>
							<label style="display:inline-block;margin-left:15px;">
								<?php esc_html_e( 'Days:', 'wp-secure-2fa' ); ?>
								<input type="number" name="wps2fa_settings[grace_period_days]" value="<?php echo esc_attr( $all['grace_period_days'] ); ?>" min="1" max="30" style="width:60px;" />
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Exempt roles', 'wp-secure-2fa' ); ?></th>
						<td>
							<?php foreach ( $roles as $role_key => $role_data ) : ?>
								<label>
									<input type="checkbox" name="wps2fa_settings[enforce_roles][]" value="<?php echo esc_attr( $role_key ); ?>" <?php checked( in_array( $role_key, $all['enforce_roles'], true ) ); ?> />
									<?php echo esc_html( $role_data['name'] ); ?>
								</label><br />
							<?php endforeach; ?>
							<p class="description"><?php esc_html_e( 'Roles that are exempt from 2FA enforcement.', 'wp-secure-2fa' ); ?></p>
						</td>
					</tr>
				</table>

				<h2 class="title"><?php esc_html_e( 'White Labeling', 'wp-secure-2fa' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'White label', 'wp-secure-2fa' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="wps2fa_settings[white_label]" value="1" <?php checked( $all['white_label'], 'yes' ); ?> />
								<?php esc_html_e( 'Enable white labeling', 'wp-secure-2fa' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="wl_plugin_name"><?php esc_html_e( 'Plugin name', 'wp-secure-2fa' ); ?></label></th>
						<td>
							<input type="text" id="wl_plugin_name" name="wps2fa_settings[wl_plugin_name]" value="<?php echo esc_attr( $all['wl_plugin_name'] ); ?>" class="regular-text" />
						</td>
					</tr>
				</table>

				<h2 class="title"><?php esc_html_e( 'Login & Remember Device', 'wp-secure-2fa' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Show QR code', 'wp-secure-2fa' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="wps2fa_settings[show_qr_code]" value="1" <?php checked( $all['show_qr_code'], 'yes' ); ?> />
								<?php esc_html_e( 'Show QR code on setup', 'wp-secure-2fa' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Remember device', 'wp-secure-2fa' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="wps2fa_settings[remember_device]" value="1" <?php checked( $all['remember_device'], 'yes' ); ?> />
								<?php esc_html_e( 'Allow users to remember their device', 'wp-secure-2fa' ); ?>
							</label>
							<label style="display:inline-block;margin-left:15px;">
								<?php esc_html_e( 'Days:', 'wp-secure-2fa' ); ?>
								<input type="number" name="wps2fa_settings[remember_days]" value="<?php echo esc_attr( $all['remember_days'] ); ?>" min="1" max="365" style="width:60px;" />
							</label>
						</td>
					</tr>
				</table>

				<p class="submit">
					<input type="submit" class="button button-primary" value="<?php esc_attr_e( 'Save Settings', 'wp-secure-2fa' ); ?>" />
				</p>
			</form>
		</div>
		<?php
	}
}
