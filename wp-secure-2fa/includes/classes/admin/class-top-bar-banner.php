<?php
/**
 * Top bar banner for 2FA status.
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Secure_2FA_Admin_Top_Bar_Banner
 *
 * Shows a status banner in the admin toolbar.
 */
class WP_Secure_2FA_Admin_Top_Bar_Banner {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Secure_2FA_Admin_Top_Bar_Banner|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Secure_2FA_Admin_Top_Bar_Banner
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
		add_action( 'admin_bar_menu', array( $this, 'add_toolbar_item' ), 90 );
	}

	/**
	 * Add admin toolbar item.
	 *
	 * @param WP_Admin_Bar $wp_admin_bar Admin bar object.
	 */
	public function add_toolbar_item( $wp_admin_bar ) {
		if ( ! is_user_logged_in() ) {
			return;
		}

		$user_id = get_current_user_id();
		$helper  = WP_Secure_2FA_User_Helper::get_instance();
		$status  = $helper->get_status( $user_id );

		if ( $status['enabled'] && $status['configured'] ) {
			$label = __( '2FA Enabled', 'wp-secure-2fa' );
			$color = '#46b450';
		} else {
			$label = __( '2FA Not Set Up', 'wp-secure-2fa' );
			$color = '#dc3232';
		}

		$wp_admin_bar->add_node(
			array(
				'id'    => 'wps2fa-status',
				'title' => $label,
				'href'  => admin_url( 'profile.php' ),
				'meta'  => array( 'style' => 'background:' . $color . ';border-radius:3px;padding:0 6px;' ),
			)
		);
	}
}
