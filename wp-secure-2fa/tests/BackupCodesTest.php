<?php
/**
 * Backup codes tests.
 *
 * @package WP_Secure_2FA
 */

/**
 * Class BackupCodesTest
 */
class BackupCodesTest extends WP_UnitTestCase {

	/**
	 * @var WP_Secure_2FA_Backup_Codes
	 */
	private $backup;

	/**
	 * @var int
	 */
	private $user_id;

	/**
	 * Set up.
	 */
	public function setUp(): void {
		parent::setUp();
		$this->backup  = WP_Secure_2FA_Backup_Codes::get_instance();
		$this->user_id = self::factory()->user->create( array( 'role' => 'administrator' ) );
	}

	/**
	 * Tear down.
	 */
	public function tearDown(): void {
		delete_user_meta( $this->user_id, 'wps2fa_backup_codes' );
		parent::tearDown();
	}

	/**
	 * Test code generation.
	 */
	public function test_generate_codes() {
		$codes = $this->backup->generate_for_user( $this->user_id );
		$this->assertNotEmpty( $codes );
		$this->assertIsArray( $codes );
		$this->assertEquals( 10, count( $codes ) );
		$this->assertTrue( $this->backup->has_codes( $this->user_id ) );
	}

	/**
	 * Test code format.
	 */
	public function test_code_format() {
		$codes = $this->backup->generate_for_user( $this->user_id );
		foreach ( $codes as $code ) {
			$this->assertEquals( 8, strlen( $code ) );
			$this->assertTrue( ctype_alnum( $code ) );
		}
	}

	/**
	 * Test code validation.
	 */
	public function test_validate_code() {
		$codes = $this->backup->generate_for_user( $this->user_id );
		$this->assertTrue( $this->backup->validate_code( $this->user_id, $codes[0] ) );
	}

	/**
	 * Test code is consumed after use.
	 */
	public function test_code_consumed() {
		$codes = $this->backup->generate_for_user( $this->user_id );
		$this->assertTrue( $this->backup->validate_code( $this->user_id, $codes[0] ) );
		// Code should be consumed.
		$this->assertFalse( $this->backup->validate_code( $this->user_id, $codes[0] ) );
		// Remaining count should be 9.
		$this->assertEquals( 9, $this->backup->get_remaining_count( $this->user_id ) );
	}

	/**
	 * Test invalid code validation.
	 */
	public function test_validate_invalid_code() {
		$this->backup->generate_for_user( $this->user_id );
		$this->assertFalse( $this->backup->validate_code( $this->user_id, 'INVALID1' ) );
		$this->assertFalse( $this->backup->validate_code( $this->user_id, '' ) );
	}

	/**
	 * Test validation without codes.
	 */
	public function test_validate_without_codes() {
		$this->assertFalse( $this->backup->validate_code( $this->user_id, 'ABCD1234' ) );
	}

	/**
	 * Test has_codes.
	 */
	public function test_has_codes() {
		$this->assertFalse( $this->backup->has_codes( $this->user_id ) );
		$this->backup->generate_for_user( $this->user_id );
		$this->assertTrue( $this->backup->has_codes( $this->user_id ) );
	}

	/**
	 * Test get_remaining_count.
	 */
	public function test_remaining_count() {
		$this->assertEquals( 0, $this->backup->get_remaining_count( $this->user_id ) );
		$this->backup->generate_for_user( $this->user_id );
		$this->assertEquals( 10, $this->backup->get_remaining_count( $this->user_id ) );

		$codes = get_user_meta( $this->user_id, 'wps2fa_backup_codes', true );
		$encryptor = WP_Secure_2FA_Open_SSL::get_instance();
		$this->assertTrue( $this->backup->validate_code( $this->user_id, $encryptor->decrypt( $codes[0] ) ) );
		$this->assertEquals( 9, $this->backup->get_remaining_count( $this->user_id ) );
	}

	/**
	 * Test delete_for_user.
	 */
	public function test_delete_for_user() {
		$this->backup->generate_for_user( $this->user_id );
		$this->assertTrue( $this->backup->has_codes( $this->user_id ) );
		$this->backup->delete_for_user( $this->user_id );
		$this->assertFalse( $this->backup->has_codes( $this->user_id ) );
	}

	/**
	 * Test regeneration produces new codes.
	 */
	public function test_regeneration() {
		$codes1 = $this->backup->generate_for_user( $this->user_id );
		$codes2 = $this->backup->generate_for_user( $this->user_id );

		// Old codes should be invalid.
		$this->assertFalse( $this->backup->validate_code( $this->user_id, $codes1[0] ) );
		// New codes should be valid.
		$this->assertTrue( $this->backup->validate_code( $this->user_id, $codes2[0] ) );
	}

	/**
	 * Test codes are unique within a set.
	 */
	public function test_codes_unique() {
		$codes = $this->backup->generate_for_user( $this->user_id );
		$unique = array_unique( $codes );
		$this->assertEquals( count( $codes ), count( $unique ) );
	}
}
