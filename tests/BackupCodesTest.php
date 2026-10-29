<?php
/**
 * Backup codes tests - generation, validation, single-use behavior.
 *
 * @package WP2FA
 */

namespace WP2FA\Tests;

use WP2FA\Methods\Backup_Codes;

/**
 * Class BackupCodesTest
 */
class BackupCodesTest extends \WP_UnitTestCase {

	/**
	 * Test user created for each test.
	 *
	 * @var \WP_User
	 */
	private $user;

	/**
	 * Set up a fresh user before each test.
	 */
	public function set_up() {
		parent::set_up();
		$this->user = self::factory()->user->create_and_get();
	}

	/**
	 * generate_codes returns the requested number of numeric codes.
	 */
	public function test_generate_codes_count() {
		$codes = Backup_Codes::generate_codes( $this->user );
		$this->assertSame( Backup_Codes::NUMBER_OF_CODES, count( $codes ) );
		foreach ( $codes as $code ) {
			$this->assertSame( 16, strlen( $code ), 'Each backup code should be 16 characters' );
			$this->assertMatchesRegularExpression( '/^\d{16}$/', $code );
		}
	}

	/**
	 * generate_codes with a custom number argument.
	 */
	public function test_generate_codes_custom_count() {
		$codes = Backup_Codes::generate_codes( $this->user, array( 'number' => 5 ) );
		$this->assertSame( 5, count( $codes ) );
	}

	/**
	 * generate_codes stores hashed codes in user meta.
	 */
	public function test_generate_codes_stored_hashed() {
		$codes = Backup_Codes::generate_codes( $this->user );
		$stored = \get_user_meta( $this->user->ID, Backup_Codes::BACKUP_CODES_META_KEY, true );

		$this->assertIsArray( $stored );
		$this->assertSame( count( $codes ), count( $stored ) );

		// Stored values must be hashes, not plain codes.
		foreach ( $stored as $hashed ) {
			$this->assertNotContains( $hashed, $codes, 'Stored values must not be plain codes' );
		}

		// Each plain code verifies against exactly one stored hash.
		foreach ( $codes as $plain ) {
			$found = false;
			foreach ( $stored as $hashed ) {
				if ( \wp_check_password( $plain, $hashed, $this->user->ID ) ) {
					$found = true;
					break;
				}
			}
			$this->assertTrue( $found, 'Each generated code should verify against a stored hash' );
		}
	}

	/**
	 * generate_codes returns unique codes.
	 */
	public function test_generate_codes_unique() {
		$codes = Backup_Codes::generate_codes( $this->user, array( 'number' => 10 ) );
		$this->assertSame( 10, count( array_unique( $codes ) ), 'Generated codes must be unique' );
	}

	/**
	 * validate_code accepts a valid backup code.
	 */
	public function test_validate_code_accepts_valid() {
		$codes = Backup_Codes::generate_codes( $this->user );
		$this->assertTrue( Backup_Codes::validate_code( $this->user, $codes[0] ) );
	}

	/**
	 * validate_code rejects an invalid code.
	 */
	public function test_validate_code_rejects_invalid() {
		Backup_Codes::generate_codes( $this->user );
		$this->assertFalse( Backup_Codes::validate_code( $this->user, '0000000000000000' ) );
	}

	/**
	 * A used backup code cannot be used again (single-use).
	 */
	public function test_validate_code_single_use() {
		$codes = Backup_Codes::generate_codes( $this->user );

		$first = Backup_Codes::validate_code( $this->user, $codes[0] );
		$this->assertTrue( $first, 'First use should succeed' );

		$second = Backup_Codes::validate_code( $this->user, $codes[0] );
		$this->assertFalse( $second, 'Second use of the same code must fail' );
	}

	/**
	 * After using one code, the remaining codes still work.
	 */
	public function test_validate_code_remaining_codes_work() {
		$codes = Backup_Codes::generate_codes( $this->user );
		Backup_Codes::validate_code( $this->user, $codes[0] );

		foreach ( array_slice( $codes, 1 ) as $code ) {
			$this->assertTrue( Backup_Codes::validate_code( $this->user, $code ), 'Remaining codes should still validate' );
		}
	}

	/**
	 * codes_remaining_for_user reflects usage.
	 */
	public function test_codes_remaining() {
		$codes = Backup_Codes::generate_codes( $this->user );

		$this->assertSame( Backup_Codes::NUMBER_OF_CODES, Backup_Codes::codes_remaining_for_user( $this->user ) );

		Backup_Codes::validate_code( $this->user, $codes[0] );
		$this->assertSame( Backup_Codes::NUMBER_OF_CODES - 1, Backup_Codes::codes_remaining_for_user( $this->user ) );
	}

	/**
	 * generate_codes with method=append adds to existing codes.
	 */
	public function test_generate_codes_append() {
		$first  = Backup_Codes::generate_codes( $this->user, array( 'number' => 3 ) );
		$second = Backup_Codes::generate_codes( $this->user, array( 'number' => 3, 'method' => 'append' ) );

		$this->assertSame( 6, Backup_Codes::codes_remaining_for_user( $this->user ), 'Append should keep the first 3 codes' );

		// Old codes still validate.
		$this->assertTrue( Backup_Codes::validate_code( $this->user, $first[0] ), 'Appended codes must not remove old ones' );
	}

	/**
	 * delete_code removes a code from the user's list.
	 */
	public function test_delete_code() {
		$codes = Backup_Codes::generate_codes( $this->user );
		$stored = \get_user_meta( $this->user->ID, Backup_Codes::BACKUP_CODES_META_KEY, true );

		// Find the hash of the first code.
		$hashed = null;
		foreach ( $stored as $h ) {
			if ( \wp_check_password( $codes[0], $h, $this->user->ID ) ) {
				$hashed = $h;
				break;
			}
		}
		$this->assertNotNull( $hashed );

		Backup_Codes::delete_code( $this->user, $hashed );

		$after = \get_user_meta( $this->user->ID, Backup_Codes::BACKUP_CODES_META_KEY, true );
		$this->assertNotContains( $hashed, $after, 'Deleted code must be gone' );
		$this->assertFalse( Backup_Codes::validate_code( $this->user, $codes[0] ) );
	}

	/**
	 * validate_code fails when the user has no codes.
	 */
	public function test_validate_code_no_codes() {
		$this->assertFalse( Backup_Codes::validate_code( $this->user, '1234567890123456' ) );
	}

	/**
	 * A code with surrounding whitespace is still accepted (normalised).
	 */
	public function test_validate_code_with_whitespace() {
		$codes = Backup_Codes::generate_codes( $this->user );
		$padded = ' ' . $codes[0] . ' ';
		$this->assertTrue( Backup_Codes::validate_code( $this->user, $padded ), 'Whitespace-padded code should be accepted' );
	}

	/**
	 * get_backup_codes_for_user returns the hashed codes stored.
	 */
	public function test_get_backup_codes_for_user() {
		Backup_Codes::generate_codes( $this->user );
		$stored = Backup_Codes::get_backup_codes_for_user( $this->user );
		$this->assertIsArray( $stored );
		$this->assertSame( Backup_Codes::NUMBER_OF_CODES, count( $stored ) );
	}
}
