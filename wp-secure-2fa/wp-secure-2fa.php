<?php
/**
 * Plugin Name:       WP Secure 2FA
 * Plugin URI:        https://wordpress.org/
 * Description:       Adds Two-Factor Authentication to WordPress using TOTP, backup codes, and email verification. Includes setup wizard, per-user management, grace period, white-labeling, and REST API.
 * Version:           1.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.2
 * Author:            Arena
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-secure-2fa
 * Domain Path:       /languages
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Core plugin constants.
 */
define( 'WP_SECURE_2FA_VERSION', '1.0.0' );
define( 'WP_SECURE_2FA_PREFIX', 'wps2fa_' );
define( 'WP_SECURE_2FA_PATH', plugin_dir_path( __FILE__ ) );
define( 'WP_SECURE_2FA_URL', plugin_dir_url( __FILE__ ) );
define( 'WP_SECURE_2FA_INC', WP_SECURE_2FA_PATH . 'includes/' );

/**
 * Autoloader for plugin classes.
 *
 * Maps class names to file paths:
 *   WP_Secure_2FA_Open_SSL            -> includes/classes/class-open-ssl.php
 *   WP_Secure_2FA_REST_API            -> includes/classes/class-rest-api.php
 *   WP_Secure_2FA_Admin_Settings_Page -> includes/classes/admin/class-settings-page.php
 *
 * @param string $class Class name.
 */
function wp_secure_2fa_autoload( $class ) {
	$prefix = 'WP_Secure_2FA_';
	$len    = strlen( $prefix );

	if ( strncmp( $prefix, $class, $len ) !== 0 ) {
		return;
	}

	$relative = substr( $class, $len );

	// Admin classes live in the admin subdirectory.
	$admin_prefix = 'Admin_';
	if ( strncmp( $relative, $admin_prefix, strlen( $admin_prefix ) ) === 0 ) {
		$relative = substr( $relative, strlen( $admin_prefix ) );
		$file     = WP_SECURE_2FA_INC . 'classes/admin/class-' . strtolower( str_replace( '_', '-', $relative ) ) . '.php';
	} else {
		$file = WP_SECURE_2FA_INC . 'classes/class-' . strtolower( str_replace( '_', '-', $relative ) ) . '.php';
	}

	if ( file_exists( $file ) ) {
		require_once $file;
	}
}

spl_autoload_register( 'wp_secure_2fa_autoload' );

/**
 * Main plugin class.
 */
final class WP_Secure_2FA {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Secure_2FA|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Secure_2FA
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
	 * Load text domain.
	 */
	private function load_textdomain() {
		load_plugin_textdomain( 'wp-secure-2fa', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
	}

	/**
	 * Include core files.
	 */
	private function includes() {
		require_once WP_SECURE_2FA_INC . 'functions/core.php';
		require_once WP_SECURE_2FA_PATH . 'templates/login-2fa.php';
		require_once WP_SECURE_2FA_INC . 'classes/class-open-ssl.php';
		require_once WP_SECURE_2FA_INC . 'classes/class-totp.php';
		require_once WP_SECURE_2FA_INC . 'classes/class-backup-codes.php';
		require_once WP_SECURE_2FA_INC . 'classes/class-email.php';
		require_once WP_SECURE_2FA_INC . 'classes/class-user-helper.php';
		require_once WP_SECURE_2FA_INC . 'classes/class-settings.php';
		require_once WP_SECURE_2FA_INC . 'classes/class-authentication.php';
		require_once WP_SECURE_2FA_INC . 'classes/class-login.php';
		require_once WP_SECURE_2FA_INC . 'classes/class-ajax.php';
		require_once WP_SECURE_2FA_INC . 'classes/class-rest-api.php';
		require_once WP_SECURE_2FA_INC . 'classes/class-grace-period.php';
		require_once WP_SECURE_2FA_INC . 'classes/admin/class-settings-page.php';
		require_once WP_SECURE_2FA_INC . 'classes/admin/class-user-profile.php';
		require_once WP_SECURE_2FA_INC . 'classes/admin/class-setup-wizard.php';
		require_once WP_SECURE_2FA_INC . 'classes/admin/class-top-bar-banner.php';
	}

	/**
	 * Initialize hooks.
	 */
	private function init_hooks() {
		// Activation / deactivation.
		register_activation_hook( __FILE__, array( $this, 'activate' ) );
		register_deactivation_hook( __FILE__, array( $this, 'deactivate' ) );

		// Init classes.
		add_action( 'plugins_loaded', array( $this, 'init' ) );

		// Assets.
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login_assets' ) );

		// Plugin update notice.
		add_action( 'admin_notices', array( $this, 'plugin_update_notice' ) );
	}

	/**
	 * Initialize plugin on plugins_loaded.
	 */
	public function init() {
		// Settings.
		WP_Secure_2FA_Settings::get_instance();

		// Authentication.
		WP_Secure_2FA_Authentication::get_instance();

		// Login.
		WP_Secure_2FA_Login::get_instance();

		// AJAX.
		WP_Secure_2FA_Ajax::get_instance();

		// REST API.
		WP_Secure_2FA_REST_API::get_instance();

		// Grace period.
		WP_Secure_2FA_Grace_Period::get_instance();

		// Admin.
		WP_Secure_2FA_Admin_Settings_Page::get_instance();
		WP_Secure_2FA_Admin_User_Profile::get_instance();
		WP_Secure_2FA_Admin_Setup_Wizard::get_instance();
		WP_Secure_2FA_Admin_Top_Bar_Banner::get_instance();

		do_action( 'wps2fa_init', $this );
	}

	/**
	 * Activation hook.
	 */
	public function activate() {
		// Set default settings.
		WP_Secure_2FA_Settings::get_instance()->set_default_settings();

		// Flush rewrite rules for REST API.
		flush_rewrite_rules();

		// Set activation transient for wizard.
		set_transient( 'wps2fa_setup_wizard', '1', 7 * DAY_IN_SECONDS );
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
		// Only load on our pages.
		if ( ! in_array( $hook, array( 'toplevel_page_wps2fa-settings', 'user_edit.php', 'user-new.php', 'profile.php', 'appearance_page_wps2fa-wizard' ), true ) ) {
			return;
		}

		wp_enqueue_style(
			'wps2fa-admin',
			WP_SECURE_2FA_URL . 'css/admin.css',
			array(),
			WP_SECURE_2FA_VERSION
		);

		wp_enqueue_script(
			'wps2fa-admin',
			WP_SECURE_2FA_URL . 'js/admin.js',
			array( 'jquery' ),
			WP_SECURE_2FA_VERSION,
			true
		);

		wp_localize_script(
			'wps2fa-admin',
			'wp_secure_2fa_admin',
			array(
				'ajaxurl'          => admin_url( 'admin-ajax.php' ),
				'totp_heading'     => __( 'Set Up TOTP', 'wp-secure-2fa' ),
				'totp_secret_label' => __( 'Secret key:', 'wp-secure-2fa' ),
				'code_label'       => __( 'Enter current code:', 'wp-secure-2fa' ),
				'verify_label'     => __( 'Verify & Save', 'wp-secure-2fa' ),
				'disable_confirm'  => __( 'Are you sure you want to disable 2FA? You will lose access if you don\'t have backup codes.', 'wp-secure-2fa' ),
				'ajax_error'       => __( 'An error occurred. Please try again.', 'wp-secure-2fa' ),
			)
		);
	}

	/**
	 * Enqueue login page assets.
	 */
	public function enqueue_login_assets() {
		wp_enqueue_style(
			'wps2fa-login',
			WP_SECURE_2FA_URL . 'css/login.css',
			array(),
			WP_SECURE_2FA_VERSION
		);
	}

	/**
	 * Plugin update notice.
	 */
	public function plugin_update_notice() {
		// Placeholder for update checks.
	}
}

/**
 * Initialize the plugin.
 *
 * @return WP_Secure_2FA
 */
function wp_secure_2fa() {
	return WP_Secure_2FA::get_instance();
}

// Kick it off.
wp_secure_2fa();
