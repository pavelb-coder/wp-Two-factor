<?php
/**
 * Plugin Name:       WP Mail 2FA
 * Plugin URI:        https://wordpress.org/
 * Description:       Two-factor authentication via email for WordPress. Users receive a one-time code on login that they enter to complete authentication.
 * Version:           1.0.2
 * Requires at least: 5.8
 * Requires PHP:      7.2
 * Author:            Arena
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-mail-2fa
 * Domain Path:       /languages
 *
 * @package WP_Mail_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Force Russian locale — must run before WordPress determines locale.
add_filter( 'locale', function() { return 'ru_RU'; } );

/**
 * Core plugin constants.
 */
define( 'WP_MAIL_2FA_VERSION', '1.0.2' );
define( 'WP_MAIL_2FA_PREFIX', 'wpm2fa_' );
define( 'WP_MAIL_2FA_PATH', plugin_dir_path( __FILE__ ) );
define( 'WP_MAIL_2FA_URL', plugin_dir_url( __FILE__ ) );
define( 'WP_MAIL_2FA_INC', WP_MAIL_2FA_PATH . 'includes/' );

/**
 * Autoloader for plugin classes.
 *
 * @param string $class Class name.
 */
function wp_mail_2fa_autoload( $class ) {
	$prefix = 'WP_Mail_2FA_';
	$len    = strlen( $prefix );

	if ( strncmp( $prefix, $class, $len ) !== 0 ) {
		return;
	}

	$relative = substr( $class, $len );

	// Admin classes live in the admin subdirectory.
	$admin_prefix = 'Admin_';
	if ( strncmp( $relative, $admin_prefix, strlen( $admin_prefix ) ) === 0 ) {
		$relative = substr( $relative, strlen( $admin_prefix ) );
		$file     = WP_MAIL_2FA_INC . 'classes/admin/class-' . strtolower( str_replace( '_', '-', $relative ) ) . '.php';
	} else {
		$file = WP_MAIL_2FA_INC . 'classes/class-' . strtolower( str_replace( '_', '-', $relative ) ) . '.php';
	}

	if ( file_exists( $file ) ) {
		require_once $file;
	}
}

spl_autoload_register( 'wp_mail_2fa_autoload' );

/**
 * Main plugin class.
 */
final class WP_Mail_2FA {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Mail_2FA|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Mail_2FA
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
		$this->load_textdomain();
		$this->includes();
		$this->init_hooks();
	}

	/**
	 * Load text domain on plugins_loaded (locale is already forced above).
	 */
	private function load_textdomain() {
		add_action( 'plugins_loaded', function() {
			load_plugin_textdomain( 'wp-mail-2fa', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
		} );
	}

	/**
	 * Include core files.
	 */
	private function includes() {
		require_once WP_MAIL_2FA_INC . 'functions/core.php';
		require_once WP_MAIL_2FA_INC . 'classes/class-email.php';
		require_once WP_MAIL_2FA_INC . 'classes/class-user-helper.php';
		require_once WP_MAIL_2FA_INC . 'classes/class-settings.php';
		require_once WP_MAIL_2FA_INC . 'classes/class-authentication.php';
		require_once WP_MAIL_2FA_INC . 'classes/class-login.php';
		require_once WP_MAIL_2FA_INC . 'classes/class-ajax.php';
		require_once WP_MAIL_2FA_INC . 'classes/class-rest-api.php';
		require_once WP_MAIL_2FA_INC . 'classes/class-grace-period.php';
		require_once WP_MAIL_2FA_INC . 'classes/admin/class-settings-page.php';
		require_once WP_MAIL_2FA_INC . 'classes/admin/class-user-profile.php';
	}

	/**
	 * Initialize hooks.
	 */
	private function init_hooks() {
		// Activation / deactivation.
		register_activation_hook( __FILE__, array( $this, 'activate' ) );
		register_deactivation_hook( __FILE__, array( $this, 'deactivate' ) );

		// Init on plugins_loaded.
		add_action( 'plugins_loaded', array( $this, 'init' ) );

		// Assets.
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login_assets' ) );
	}

	/**
	 * Initialize plugin on plugins_loaded.
	 */
	public function init() {
		// Settings.
		WP_Mail_2FA_Settings::get_instance();

		// Authentication.
		WP_Mail_2FA_Authentication::get_instance();

		// Login.
		WP_Mail_2FA_Login::get_instance();

		// AJAX.
		WP_Mail_2FA_Ajax::get_instance();

		// REST API.
		WP_Mail_2FA_REST_API::get_instance();

		// Grace period.
		WP_Mail_2FA_Grace_Period::get_instance();

		// Admin.
		WP_Mail_2FA_Admin_Settings_Page::get_instance();
		WP_Mail_2FA_Admin_User_Profile::get_instance();

		do_action( 'wpm2fa_init', $this );
	}

	/**
	 * Activation hook.
	 */
	public function activate() {
		// Set default settings.
		WP_Mail_2FA_Settings::get_instance()->set_default_settings();

		// Flush rewrite rules for REST API.
		flush_rewrite_rules();
	}

	/**
	 * Deactivation hook.
	 */
	public function deactivate() {
		flush_rewrite_rules();
	}

	/**
	 * Enqueue admin assets.
	 *
	 * @param string $hook Current admin page hook.
	 */
	public function enqueue_admin_assets( $hook ) {
		if ( ! in_array( $hook, array( 'toplevel_page_wpm2fa-settings', 'user_edit.php', 'user-new.php', 'profile.php' ), true ) ) {
			return;
		}

		wp_enqueue_style(
			'wpm2fa-admin',
			WP_MAIL_2FA_URL . 'css/admin.css',
			array(),
			WP_MAIL_2FA_VERSION
		);

		wp_enqueue_script(
			'wpm2fa-admin',
			WP_MAIL_2FA_URL . 'js/admin.js',
			array( 'jquery' ),
			WP_MAIL_2FA_VERSION,
			true
		);

		wp_localize_script(
			'wpm2fa-admin',
			'wp_mail_2fa_admin',
			array(
				'ajaxurl'        => admin_url( 'admin-ajax.php' ),
				'send_test_email' => __( 'Отправить тестовое email', 'wp-mail-2fa' ),
				'ajax_error'     => __( 'Произошла ошибка. Попробуйте снова.', 'wp-mail-2fa' ),
			)
		);
	}

	/**
	 * Enqueue login page assets.
	 */
	public function enqueue_login_assets() {
		wp_enqueue_style(
			'wpm2fa-login',
			WP_MAIL_2FA_URL . 'css/login.css',
			array(),
			WP_MAIL_2FA_VERSION
		);
	}
}

/**
 * Initialize the plugin.
 *
 * @return WP_Mail_2FA
 */
function wp_mail_2fa() {
	return WP_Mail_2FA::get_instance();
}

// Kick it off.
wp_mail_2fa();
