/**
 * WP Secure 2FA — Admin JavaScript.
 */

( function( $ ) {
	'use strict';

	// Setup TOTP button.
	$( document ).on( 'click', '.wps2fa-setup-totp', function( e ) {
		e.preventDefault();
		var userId = $( this ).data( 'user-id' );
		var nonce = $( this ).data( 'nonce' );
		var container = $( '#wps2fa-setup-container' );

		container.html( '<p class="wps2fa-loading"></p>' );

		$.ajax( {
			url: ajaxurl,
			type: 'POST',
			data: {
				action: 'wps2fa_generate_totp',
				user_id: userId,
				nonce: nonce
			},
			success: function( response ) {
				if ( response.success ) {
					var data = response.data;
					container.html(
						'<h3>' + wp_secure_2fa_admin.totp_heading + '</h3>'
						+ '<p>' + wp_secure_2fa_admin.totp_secret_label + '</p>'
						+ '<div class="wps2fa-totp-secret">' + data.secret + '</div>'
						+ '<div class="wps2fa-qr-code"><img src="' + data.authcode_url.replace( 'otpauth://', 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=' ) + '" alt="QR Code" /></div>'
						+ '<div class="field"><label>' + wp_secure_2fa_admin.code_label + '</label>'
						+ '<input type="text" id="wps2fa-totp-code" placeholder="000000" maxlength="6" /></div>'
						+ '<button class="button button-primary wps2fa-verify-totp" data-user-id="' + userId + '" data-nonce="' + nonce + '">' + wp_secure_2fa_admin.verify_label + '</button>'
				);
			} else {
				container.html( '<div class="error"><p>' + response.data.message + '</p></div>' );
			}
		},
		error: function() {
			container.html( '<div class="error"><p>' + wp_secure_2fa_admin.ajax_error + '</p></div>' );
		}
		} );
	} );

	// Verify TOTP button.
	$( document ).on( 'click', '.wps2fa-verify-totp', function( e ) {
		e.preventDefault();
		var userId = $( this ).data( 'user-id' );
		var nonce = $( this ).data( 'nonce' );
		var code = $( '#wps2fa-totp-code' ).val();

		$.ajax( {
			url: ajaxurl,
			type: 'POST',
			data: {
				action: 'wps2fa_verify_totp',
				user_id: userId,
				code: code,
				nonce: nonce
			},
			success: function( response ) {
				if ( response.success ) {
					$( '#wps2fa-setup-container' ).html( '<div class="notice notice-success"><p>' + response.data.message + '</p></div>' );
				} else {
					$( '#wps2fa-setup-container' ).html( '<div class="error"><p>' + response.data.message + '</p></div>' );
				}
			}
		} );
	} );

	// Generate backup codes.
	$( document ).on( 'click', '.wps2fa-generate-backup, .wps2fa-regenerate-backup', function( e ) {
		e.preventDefault();
		var userId = $( this ).data( 'user-id' );
		var nonce = $( this ).data( 'nonce' );
		var container = $( '#wps2fa-backup-container' );

		$.ajax( {
			url: ajaxurl,
			type: 'POST',
			data: {
				action: 'wps2fa_generate_backup_codes',
				user_id: userId,
				nonce: nonce
			},
			success: function( response ) {
				if ( response.success ) {
					var codes = response.data.codes.join( '\n' );
					container.find( '#wps2fa-backup-codes' ).val( codes );
					container.slideDown();
				} else {
					alert( response.data.message );
				}
			}
		} );
	} );

	// Setup email.
	$( document ).on( 'click', '.wps2fa-setup-email', function( e ) {
		e.preventDefault();
		var userId = $( this ).data( 'user-id' );
		var nonce = $( this ).data( 'nonce' );

		$.ajax( {
			url: ajaxurl,
			type: 'POST',
			data: {
				action: 'wps2fa_send_email_code',
				user_id: userId,
				nonce: nonce
			},
			success: function( response ) {
				if ( response.success ) {
					$( '#wps2fa-setup-container' ).html( '<div class="notice notice-success"><p>' + response.data.message + '</p></div>' );
				} else {
					$( '#wps2fa-setup-container' ).html( '<div class="error"><p>' + response.data.message + '</p></div>' );
				}
			}
		} );
	} );

	// Disable 2FA.
	$( document ).on( 'click', '.wps2fa-disable', function( e ) {
		e.preventDefault();
		var userId = $( this ).data( 'user-id' );
		var nonce = $( this ).data( 'nonce' );

		if ( ! confirm( wp_secure_2fa_admin.disable_confirm ) ) {
			return;
		}

		$.ajax( {
			url: ajaxurl,
			type: 'POST',
			data: {
				action: 'wps2fa_disable_2fa',
				user_id: userId,
				nonce: nonce
			},
			success: function( response ) {
				if ( response.success ) {
					location.reload();
				} else {
					alert( response.data.message );
				}
			}
		} );
	} );

} )( jQuery );
