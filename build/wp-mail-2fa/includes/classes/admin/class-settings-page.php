<?php
/**
 * Admin settings page.
 *
 * @package WP_Mail_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Mail_2FA_Admin_Settings_Page
 *
 * Registers and renders the plugin settings page.
 */
class WP_Mail_2FA_Admin_Settings_Page {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Mail_2FA_Admin_Settings_Page|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Mail_2FA_Admin_Settings_Page
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
		add_filter( 'plugin_action_links_' . plugin_basename( WP_MAIL_2FA_PATH . 'wp-mail-2fa.php' ), array( $this, 'add_action_link' ) );
	}

	/**
	 * Register admin menu.
	 */
	public function register_menu() {
		add_options_page(
			__( 'Настройки WP Mail 2FA', 'wp-mail-2fa' ),
			__( 'WP Mail 2FA', 'wp-mail-2fa' ),
			'manage_options',
			'wpm2fa-settings',
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
		$settings_link = '<a href="' . esc_url( admin_url( 'options-general.php?page=wpm2fa-settings' ) ) . '">' . esc_html__( 'Настройки', 'wp-mail-2fa' ) . '</a>';
		array_unshift( $links, $settings_link );
		return $links;
	}

	/**
	 * Handle settings save.
	 */
	public function handle_save() {
		if ( ! isset( $_POST['wpm2fa_settings'] ) ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], 'wpm2fa_settings' ) ) {
			return;
		}

		$settings = $_POST['wpm2fa_settings'];
		$sanitized = WP_Mail_2FA_Settings::get_instance()->sanitize( $settings );

		WP_Mail_2FA_Settings::get_instance()->save( $sanitized );

		add_action( 'admin_notices', array( $this, 'show_saved_notice' ) );
	}

	/**
	 * Show settings saved notice.
	 */
	public function show_saved_notice() {
		echo '<div class="notice notice-success"><p>' . esc_html__( 'Настройки успешно сохранены.', 'wp-mail-2fa' ) . '</p></div>';
	}

	/**
	 * Render settings page.
	 */
	public function render_page() {
		$settings = WP_Mail_2FA_Settings::get_instance();
		$all      = $settings->get_all();
		$roles    = get_editable_roles();

		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Настройки WP Mail 2FA', 'wp-mail-2fa' ); ?></h1>

			<form method="post" action="">
				<?php wp_nonce_field( 'wpm2fa_settings' ); ?>

				<h2 class="title"><?php esc_html_e( 'Настройки электронной почты', 'wp-mail-2fa' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><label for="email_from_name"><?php esc_html_e( 'Имя отправителя', 'wp-mail-2fa' ); ?></label></th>
						<td>
							<input type="text" id="email_from_name" name="wpm2fa_settings[email_from_name]" value="<?php echo esc_attr( $all['email_from_name'] ); ?>" class="regular-text" />
							<p class="description"><?php esc_html_e( 'Имя, которое отображается как отправитель 2FA писем.', 'wp-mail-2fa' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="email_subject_prefix"><?php esc_html_e( 'Префикс темы', 'wp-mail-2fa' ); ?></label></th>
						<td>
							<input type="text" id="email_subject_prefix" name="wpm2fa_settings[email_subject_prefix]" value="<?php echo esc_attr( $all['email_subject_prefix'] ); ?>" />
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="code_length"><?php esc_html_e( 'Длина кода', 'wp-mail-2fa' ); ?></label></th>
						<td>
							<select id="code_length" name="wpm2fa_settings[code_length]">
								<?php for ( $len = 4; $len <= 8; $len++ ) : ?>
									<option value="<?php echo esc_attr( $len ); ?>" <?php selected( $all['code_length'], $len ); ?>><?php echo esc_html( $len ); ?></option>
								<?php endfor; ?>
							</select>
							<p class="description"><?php esc_html_e( 'Количество цифр в коде подтверждения.', 'wp-mail-2fa' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="code_expiry_minutes"><?php esc_html_e( 'Срок действия кода (минуты)', 'wp-mail-2fa' ); ?></label></th>
						<td>
							<input type="number" id="code_expiry_minutes" name="wpm2fa_settings[code_expiry_minutes]" value="<?php echo esc_attr( $all['code_expiry_minutes'] ); ?>" min="1" max="60" />
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="resend_delay_seconds"><?php esc_html_e( 'Задержка переотправки (секунды)', 'wp-mail-2fa' ); ?></label></th>
						<td>
							<input type="number" id="resend_delay_seconds" name="wpm2fa_settings[resend_delay_seconds]" value="<?php echo esc_attr( $all['resend_delay_seconds'] ); ?>" min="0" max="300" />
							<p class="description"><?php esc_html_e( 'Минимальная задержка между переотправками кода.', 'wp-mail-2fa' ); ?></p>
						</td>
					</tr>
				</table>

				<h2 class="title"><?php esc_html_e( 'Применение', 'wp-mail-2fa' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Требовать 2FA', 'wp-mail-2fa' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="wpm2fa_settings[enforce_2fa]" value="1" <?php checked( $all['enforce_2fa'], 'yes' ); ?> />
								<?php esc_html_e( 'Требовать email 2FA для всех пользователей', 'wp-mail-2fa' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Срок отсрочки', 'wp-mail-2fa' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="wpm2fa_settings[grace_period_enabled]" value="1" <?php checked( $all['grace_period_enabled'], 'yes' ); ?> />
								<?php esc_html_e( 'Включить срок отсрочки', 'wp-mail-2fa' ); ?>
							</label>
							<label style="display:inline-block;margin-left:15px;">
								<?php esc_html_e( 'Дни:', 'wp-mail-2fa' ); ?>
								<input type="number" name="wpm2fa_settings[grace_period_days]" value="<?php echo esc_attr( $all['grace_period_days'] ); ?>" min="1" max="30" style="width:60px;" />
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Исключенные роли', 'wp-mail-2fa' ); ?></th>
						<td>
							<?php foreach ( $roles as $role_key => $role_data ) : ?>
								<label>
									<input type="checkbox" name="wpm2fa_settings[enforce_roles][]" value="<?php echo esc_attr( $role_key ); ?>" <?php checked( in_array( $role_key, $all['enforce_roles'], true ) ); ?> />
									<?php echo esc_html( $role_data['name'] ); ?>
								</label><br />
							<?php endforeach; ?>
							<p class="description"><?php esc_html_e( 'Роли, которые исключены из требования 2FA.', 'wp-mail-2fa' ); ?></p>
						</td>
					</tr>
				</table>

				<h2 class="title"><?php esc_html_e( 'Вход и отображение', 'wp-mail-2fa' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Показать ссылку на настройку', 'wp-mail-2fa' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="wpm2fa_settings[show_setup_link]" value="1" <?php checked( $all['show_setup_link'], 'yes' ); ?> />
								<?php esc_html_e( 'Показать ссылку на настройку на странице входа', 'wp-mail-2fa' ); ?>
							</label>
						</td>
					</tr>
				</table>

				<h2 class="title"><?php esc_html_e( 'White Labeling', 'wp-mail-2fa' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'White label', 'wp-mail-2fa' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="wpm2fa_settings[white_label]" value="1" <?php checked( $all['white_label'], 'yes' ); ?> />
								<?php esc_html_e( 'Включить white labeling', 'wp-mail-2fa' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="wl_plugin_name"><?php esc_html_e( 'Название плагина', 'wp-mail-2fa' ); ?></label></th>
						<td>
							<input type="text" id="wl_plugin_name" name="wpm2fa_settings[wl_plugin_name]" value="<?php echo esc_attr( $all['wl_plugin_name'] ); ?>" class="regular-text" />
						</td>
					</tr>
				</table>

				<p class="submit">
					<input type="submit" class="button button-primary" value="<?php esc_attr_e( 'Сохранить настройки', 'wp-mail-2fa' ); ?>" />
				</p>
			</form>
		</div>
		<?php
	}
}
