<?php
/**
 * Plugin settings management.
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Secure_2FA_Settings
 *
 * Manages plugin-wide settings with defaults, getters, and save logic.
 */
class WP_Secure_2FA_Settings {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Secure_2FA_Settings|null
	 */
	private static $instance = null;

	/**
	 * Option name in wp_options.
	 */
	const OPTION_NAME = 'wps2fa_settings';

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Secure_2FA_Settings
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Default settings.
	 *
	 * @return array
	 */
	public function get_defaults() {
		return array(
			// Enabled methods.
			'enable_totp'          => 'yes',
			'enable_backup_codes'  => 'yes',
			'enable_email'         => 'yes',

			// Enforcement.
			'enforce_2fa'          => 'no',
			'enforce_roles'        => array(),
			'enforce_users'        => array(),

			// Grace period.
			'grace_period_enabled'  => 'yes',
			'grace_period_days'     => 7,

			// TOTP settings.
			'totp_issuer'          => get_bloginfo( 'name' ),
			'totp_period'          => 30,
			'totp_digits'          => 6,
			'totp_algorithm'       => 'sha1',

			// Backup codes.
			'backup_codes_count'   => 10,

			// White labeling.
			'white_label'          => 'no',
			'wl_plugin_name'       => 'WP Secure 2FA',

			// Login page.
			'show_qr_code'         => 'yes',
			'remember_device'      => 'yes',
			'remember_days'        => 30,

			// Misc.
			'email_from_name'      => get_bloginfo( 'name' ),
			'email_subject_prefix' => '[2FA] ',
		);
	}

	/**
	 * Get all settings.
	 *
	 * @return array
	 */
	public function get_all() {
		$defaults = $this->get_defaults();
		$saved    = get_option( self::OPTION_NAME, array() );

		return wp_parse_args( $saved, $defaults );
	}

	/**
	 * Get a single setting.
	 *
	 * @param string $key     Setting key.
	 * @param mixed  $default Default value.
	 * @return mixed
	 */
	public function get( $key, $default = null ) {
		$all = $this->get_all();

		if ( array_key_exists( $key, $all ) ) {
			return $all[ $key ];
		}

		return $default;
	}

	/**
	 * Save settings.
	 *
	 * @param array $settings Settings array to save.
	 * @return bool True on success.
	 */
	public function save( $settings ) {
		// Merge with existing.
		$current = $this->get_all();
		$updated = wp_parse_args( $settings, $current );

		return update_option( self::OPTION_NAME, $updated );
	}

	/**
	 * Set default settings on activation.
	 */
	public function set_default_settings() {
		$defaults = $this->get_defaults();
		update_option( self::OPTION_NAME, $defaults );
	}

	/**
	 * Check if a method is enabled.
	 *
	 * @param string $method Method key (enable_totp, etc).
	 * @return bool True if enabled.
	 */
	public function is_method_enabled( $method ) {
		return 'yes' === $this->get( $method, 'no' );
	}

	/**
	 * Get enabled methods.
	 *
	 * @return array Array of enabled method keys.
	 */
	public function get_enabled_methods() {
		$methods = array();

		if ( $this->is_method_enabled( 'enable_totp' ) ) {
			$methods[] = 'totp';
		}
		if ( $this->is_method_enabled( 'enable_backup_codes' ) ) {
			$methods[] = 'backup_codes';
		}
		if ( $this->is_method_enabled( 'enable_email' ) ) {
			$methods[] = 'email';
		}

		return $methods;
	}

	/**
	 * Check if 2FA is enforced for a user.
	 *
	 * @param int $user_id User ID.
	 * @return bool True if enforcement applies.
	 */
	public function is_enforced( $user_id ) {
		if ( 'yes' !== $this->get( 'enforce_2fa' ) ) {
			return false;
		}

		// Check specific user list.
		$enforced_users = (array) $this->get( 'enforce_users', array() );
		if ( in_array( $user_id, $enforced_users, true ) ) {
			return true;
		}

		// Check roles.
		$enforced_roles = (array) $this->get( 'enforce_roles', array() );
		if ( empty( $enforced_roles ) ) {
			return true; // All roles.
		}

		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return false;
		}

		return array_intersect( $enforced_roles, $user->roles );
	}

	/**
	 * Sanitize settings on save.
	 *
	 * @param array $input Raw input.
	 * @return array Sanitized.
	 */
	public function sanitize( $input ) {
		$output = array();

		// Boolean fields.
		$bool_fields = array(
			'enable_totp',
			'enable_backup_codes',
			'enable_email',
			'enforce_2fa',
			'grace_period_enabled',
			'white_label',
			'show_qr_code',
			'remember_device',
		);

		foreach ( $bool_fields as $field ) {
			$output[ $field ] = isset( $input[ $field ] ) ? 'yes' : 'no';
		}

		// Integer fields.
		$int_fields = array(
			'totp_period'      => 30,
			'totp_digits'      => 6,
			'backup_codes_count' => 10,
			'grace_period_days'  => 7,
			'remember_days'      => 30,
		);

		foreach ( $int_fields as $field => $default ) {
			if ( isset( $input[ $field ] ) && is_numeric( $input[ $field ] ) && (int) $input[ $field ] > 0 ) {
				$output[ $field ] = (int) $input[ $field ];
			} else {
				$output[ $field ] = $default;
			}
		}

		// String fields.
		$str_fields = array(
			'totp_issuer',
			'totp_algorithm',
			'wl_plugin_name',
			'email_from_name',
			'email_subject_prefix',
		);

		foreach ( $str_fields as $field ) {
			if ( isset( $input[ $field ] ) ) {
				$output[ $field ] = sanitize_text_field( $input[ $field ] );
			}
		}

		// Array fields.
		$output['enforce_roles'] = isset( $input['enforce_roles'] ) ? array_map( 'sanitize_text_field', (array) $input['enforce_roles'] ) : array();
		$output['enforce_users'] = isset( $input['enforce_users'] ) ? array_map( 'absint', (array) $input['enforce_users'] ) : array();

		return $output;
	}
}
