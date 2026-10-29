<?php
/**
 * TOTP (Time-based One-Time Password) implementation.
 *
 * RFC 6238 compliant TOTP generation and verification.
 * Supports SHA1, SHA256, SHA512.
 *
 * @package WP_Secure_2FA
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WP_Secure_2FA_TOTP
 *
 * Generates and validates RFC 6238 TOTP codes.
 */
class WP_Secure_2FA_TOTP {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Secure_2FA_TOTP|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return WP_Secure_2FA_TOTP
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Generate a new TOTP secret (base32 encoded).
	 *
	 * @param int $bytes Number of random bytes (default 20 = 160 bits).
	 * @return string Base32 encoded secret.
	 */
	public function generate_secret( $bytes = 20 ) {
		$raw = random_bytes( $bytes );
		return $this->base32_encode( $raw );
	}

	/**
	 * Generate a TOTP code for a given secret.
	 *
	 * @param string $secret    Base32 encoded secret.
	 * @param int    $timestamp Timestamp (defaults to current time).
	 * @param int    $period    Time step in seconds (default 30).
	 * @param int    $digits    Number of digits (default 6).
	 * @param string $algorithm Hash algorithm: sha1, sha256, sha512 (default sha1).
	 * @return string|false TOTP code, or false on failure.
	 */
	public function generate( $secret, $timestamp = null, $period = 30, $digits = 6, $algorithm = 'sha1' ) {
		$timestamp = $timestamp ? $timestamp : time();
		$timestamp = (int) floor( $timestamp / $period );

		// Convert base32 secret to binary.
		$secret_binary = $this->base32_decode( $secret );
		if ( false === $secret_binary || empty( $secret_binary ) ) {
			return false;
		}

		// Pack timestamp into 64-bit big-endian.
		$msg = pack( 'J', $timestamp );

		// Compute HMAC.
		$hash = hash_hmac( $algorithm, $msg, $secret_binary, true );

		// Dynamic truncation.
		$offset = ord( substr( $hash, strlen( $hash ) - 1 ) ) & 0x0f;
		$bin    = substr( $hash, $offset, 4 );

		// Convert to integer and mask.
		$code = ( ( ord( $bin[0] ) & 0x7f ) << 24 )
			| ( ( ord( $bin[1] ) & 0xff ) << 16 )
			| ( ( ord( $bin[2] ) & 0xff ) << 8 )
			| ( ord( $bin[3] ) & 0xff );

		$code = $code % (int) pow( 10, $digits );

		return str_pad( (string) $code, $digits, '0', STR_PAD_LEFT );
	}

	/**
	 * Verify a TOTP code against a secret.
	 *
	 * @param string $code      TOTP code to verify.
	 * @param string $secret    Base32 encoded secret.
	 * @param int    $window    Acceptance window in steps (default 1 = ±30 seconds).
	 * @param int    $period    Time step in seconds (default 30).
	 * @param int    $digits    Number of digits (default 6).
	 * @param string $algorithm Hash algorithm: sha1, sha256, sha512 (default sha1).
	 * @return bool True if valid.
	 */
	public function verify( $code, $secret, $window = 1, $period = 30, $digits = 6, $algorithm = 'sha1' ) {
		if ( empty( $code ) || empty( $secret ) ) {
			return false;
		}

		$code = trim( (string) $code );

		if ( ! ctype_digit( $code ) ) {
			return false;
		}

		$timestamp = time();

		// Check current step and surrounding steps.
		for ( $i = -$window; $i <= $window; $i++ ) {
			$generated = $this->generate( $secret, $timestamp + ( $i * $period ), $period, $digits, $algorithm );
			if ( false !== $generated && hash_equals( $generated, $code ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Base32 encode.
	 *
	 * @param string $data Raw binary data.
	 * @return string Base32 encoded string.
	 */
	public function base32_encode( $data ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$result   = '';
		$data     = (string) $data;
		$len      = strlen( $data );
		$bits     = 0;
		$value    = 0;

		for ( $i = 0; $i < $len; $i++ ) {
			$value   = ( $value << 8 ) | ord( $data[ $i ] );
			$bits    += 8;

			while ( $bits >= 5 ) {
				$result .= $alphabet[ ( $value >> ( $bits - 5 ) ) & 31 ];
				$bits   -= 5;
			}
		}

		if ( $bits > 0 ) {
			$result .= $alphabet[ ( $value << ( 5 - $bits ) ) & 31 ];
		}

		return $result;
	}

	/**
	 * Base32 decode.
	 *
	 * @param string $data Base32 encoded string.
	 * @return string|false Decoded binary data, or false on failure.
	 */
	public function base32_decode( $data ) {
		$data = strtoupper( (string) $data );
		$data = str_replace( array( '=', ' ', '-', '_' ), '', $data );

		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$result   = '';
		$len      = strlen( $data );
		$bits     = 0;
		$value    = 0;

		for ( $i = 0; $i < $len; $i++ ) {
			$pos = strpos( $alphabet, $data[ $i ] );
			if ( false === $pos ) {
				return false;
			}

			$value   = ( $value << 5 ) | $pos;
			$bits    += 5;

			if ( $bits >= 8 ) {
				$result .= chr( ( $value >> ( $bits - 8 ) ) & 0xff );
				$bits   -= 8;
			}
		}

		return $result;
	}

	/**
	 * Generate a TOTP authcode URL for QR code / authenticator apps.
	 *
	 * @param string $secret    Base32 encoded secret.
	 * @param string $issuer    Issuer name.
	 * @param string $account   Account name.
	 * @return string OTPAuth URL.
	 */
	public function get_authcode_url( $secret, $issuer, $account ) {
		$issuer  = rawurlencode( $issuer );
		$account = rawurlencode( $account );
		$secret  = rawurlencode( $secret );

		return 'otpauth://totp/' . $issuer . ':' . $account
			. '?secret=' . $secret
			. '&issuer=' . $issuer
			. '&algorithm=SHA1&digits=6&period=30';
	}
}
