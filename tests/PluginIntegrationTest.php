<?php
/**
 * Plugin integration tests - activation, hooks, structure.
 *
 * @package WP2FA
 */

namespace WP2FA\Tests;

use WP2FA\WP2FA;
use WP2FA\Authenticator\Authentication;
use WP2FA\Methods\Backup_Codes;
use WP2FA\Methods\TOTP;

/**
 * Class PluginIntegrationTest
 */
class PluginIntegrationTest extends \WP_UnitTestCase {

	/**
	 * Plugin header is valid and readable.
	 */
	public function test_plugin_header() {
		$plugin_file = '/tmp/wordpress-develop/src/wp-content/plugins/wp-Two-factor/wp-2fa.php';
		$data        = \get_plugin_data( $plugin_file );

		$this->assertArrayHasKey( 'Name', $data );
		$this->assertArrayHasKey( 'Version', $data );
		$this->assertArrayHasKey( 'Description', $data );
		$this->assertArrayHasKey( 'Author', $data );
		$this->assertStringContainsString( 'Two-factor authentication', $data['Name'] );
		$this->assertSame( '4.2.1', $data['Version'] );
	}

	/**
	 * Plugin constants are defined.
	 */
	public function test_plugin_constants() {
		$this->assertTrue( defined( 'WP_2FA_VERSION' ) );
		$this->assertTrue( defined( 'WP_2FA_PREFIX' ) );
		$this->assertTrue( defined( 'WP_2FA_PATH' ) );
		$this->assertTrue( defined( 'WP_2FA_INC' ) );
		$this->assertTrue( defined( 'WP_2FA_URL' ) );

		$this->assertSame( '4.2.1', WP_2FA_VERSION );
		$this->assertSame( 'wp_2fa_', WP_2FA_PREFIX );
		$this->assertStringEndsWith( 'wp-Two-factor/', WP_2FA_PATH );
		$this->assertStringEndsWith( 'includes/', WP_2FA_INC );
	}

	/**
	 * Autoloader can load plugin classes.
	 */
	public function test_autoloader_classes() {
		$classes = array(
			'\\WP2FA\\WP2FA',
			'\\WP2FA\\Authenticator\\Authentication',
			'\\WP2FA\\Authenticator\\Login',
			'\\WP2FA\\Authenticator\\Open_SSL',
			'\\WP2FA\\Methods\\Backup_Codes',
			'\\WP2FA\\Methods\\TOTP',
			'\\WP2FA\\Admin\\Helpers\\User_Helper',
			'\\WP2FA\\Utils\\Settings_Utils',
			'\\WP2FA\\Admin\\Settings_Builder',
		);
		foreach ( $classes as $class ) {
			$this->assertTrue( class_exists( $class ), "Class {$class} should be autoloadable" );
		}
	}

	/**
	 * The plugin registers its key filters (prefixed with wp_2fa_).
	 */
	public function test_plugin_filters_registered() {
		$this->assertTrue( \has_filter( 'wp_2fa_default_settings' ), 'wp_2fa_default_settings filter should be registered' );
		$this->assertTrue( \has_filter( 'wp_2fa_available_2fa_methods' ), 'wp_2fa_available_2fa_methods filter should be registered' );
		$this->assertTrue( \has_filter( 'wp_2fa_validate_login_form' ), 'wp_2fa_validate_login_form filter should be registered' );
		$this->assertTrue( \has_filter( 'wp_2fa_validate_login_api' ), 'wp_2fa_validate_login_api filter should be registered' );
		$this->assertTrue( \has_filter( 'wp_2fa_backup_methods_list' ), 'wp_2fa_backup_methods_list filter should be registered' );
		$this->assertTrue( \has_filter( 'wp_2fa_backup_methods_enabled' ), 'wp_2fa_backup_methods_enabled filter should be registered' );
		$this->assertTrue( \has_filter( 'wp_2fa_loop_settings' ), 'wp_2fa_loop_settings filter should be registered' );
		$this->assertTrue( \has_filter( 'wp_2fa_providers_translated_names' ), 'wp_2fa_providers_translated_names filter should be registered' );
	}

	/**
	 * Activation and deactivation hooks are registered.
	 */
	public function test_activation_hook_registered() {
		$this->assertTrue( \has_action( 'activate_wp-Two-factor/wp-2fa.php' ), 'Activation hook should be registered' );
		$this->assertTrue( \has_action( 'deactivate_wp-Two-factor/wp-2fa.php' ), 'Deactivation hook should be registered' );
	}

	/**
	 * Default settings are defined by the plugin (flat array structure).
	 */
	public function test_default_settings_structure() {
		$defaults = \apply_filters( 'wp_2fa_default_settings', array() );
		$this->assertNotEmpty( $defaults );
		$this->assertArrayHasKey( 'backup_codes_enabled', $defaults );
		$this->assertArrayHasKey( 'enable_email', $defaults );
		$this->assertArrayHasKey( 'enable_totp', $defaults );
		$this->assertArrayHasKey( 'wp_2fa_white_label', $defaults );
	}

	/**
	 * Backup codes default settings are present.
	 */
	public function test_backup_codes_default_settings() {
		$defaults = \apply_filters( 'wp_2fa_default_settings', array() );
		$this->assertSame( 'yes', $defaults['backup_codes_enabled'] );
	}

	/**
	 * TOTP default settings are present.
	 */
	public function test_totp_default_settings() {
		$defaults = \apply_filters( 'wp_2fa_default_settings', array() );
		$this->assertSame( 'enable_totp', $defaults['enable_totp'] );
	}

	/**
	 * The plugin directory structure contains all expected assets.
	 */
	public function test_plugin_directory_structure() {
		$base = WP_2FA_PATH;

		$this->assertDirectoryExists( $base . 'includes/' );
		$this->assertDirectoryExists( $base . 'includes/classes/' );
		$this->assertDirectoryExists( $base . 'includes/functions/' );
		$this->assertDirectoryExists( $base . 'vendor/' );
		$this->assertDirectoryExists( $base . 'dist/' );
		$this->assertDirectoryExists( $base . 'css/' );
		$this->assertDirectoryExists( $base . 'js/' );
		$this->assertDirectoryExists( $base . 'templates/' );
		$this->assertDirectoryExists( $base . 'languages/' );
		$this->assertFileExists( $base . 'wp-2fa.php' );
		$this->assertFileExists( $base . 'readme.txt' );
		$this->assertFileExists( $base . 'license.txt' );
		$this->assertFileExists( $base . 'index.php' );
		$this->assertFileExists( $base . 'vendor/autoload.php' );
	}

	/**
	 * Composer autoloader is functional.
	 */
	public function test_composer_autoloader() {
		$loader = require WP_2FA_PATH . 'vendor/autoload.php';
		$this->assertInstanceOf( \Composer\Autoload\ClassLoader::class, $loader );
	}

	/**
	 * Vendor libraries are present (BaconQrCode, Dasprid\Enum).
	 */
	public function test_vendor_libraries_present() {
		$this->assertTrue( class_exists( '\\WP2FA_Vendor\\BaconQrCode\\Writer' ), 'BaconQrCode Writer should be available' );
		$this->assertTrue( class_exists( '\\WP2FA_Vendor\\BaconQrCode\\Renderer\\ImageRenderer' ), 'BaconQrCode ImageRenderer should be available' );
	}

	/**
	 * Plugin requires PHP 7.4+ and WordPress 5.7+ (header check).
	 */
	public function test_plugin_requirements_header() {
		$plugin_file = '/tmp/wordpress-develop/src/wp-content/plugins/wp-Two-factor/wp-2fa.php';
		$data        = \get_plugin_data( $plugin_file );

		$this->assertArrayHasKey( 'RequiresWP', $data );
		$this->assertArrayHasKey( 'RequiresPHP', $data );
		$this->assertSame( '5.7', $data['RequiresWP'] );
		$this->assertSame( '7.4', $data['RequiresPHP'] );
	}

	/**
	 * The plugin main class instance can be created.
	 */
	public function test_plugin_main_class() {
		$this->assertTrue( class_exists( '\\WP2FA\\WP2FA' ) );
		$instance = new \WP2FA\WP2FA();
		$this->assertInstanceOf( '\\WP2FA\\WP2FA', $instance );
	}

	/**
	 * User meta keys used by the plugin are consistent with the constants.
	 */
	public function test_user_meta_keys_consistency() {
		$this->assertSame( 'wp_2fa_backup_codes', Backup_Codes::BACKUP_CODES_META_KEY );
		$this->assertSame( WP_2FA_PREFIX . 'totp_key', TOTP::TOTP_META_KEY );
	}

	/**
	 * Text domain is registered.
	 */
	public function test_text_domain() {
		$this->assertSame( 'wp-2fa', WP_2FA_TEXTDOMAIN );
	}

	/**
	 * The available 2FA methods filter returns TOTP and backup_codes
	 * when their policy settings are enabled.
	 */
	public function test_available_2fa_methods_filter() {
		$methods = \apply_filters( 'wp_2fa_available_2fa_methods', array(), 'administrator' );
		$this->assertIsArray( $methods );
	}

	/**
	 * Backup methods list includes the backup_codes method.
	 */
	public function test_backup_methods_list() {
		$methods = \apply_filters( 'wp_2fa_backup_methods_list', array(), 'administrator' );
		$this->assertArrayHasKey( 'backup_codes', $methods );
	}
}
