/**
 * WP Mail 2FA — Admin JavaScript.
 */

( function( $ ) {
	'use strict';

	// Enable 2FA.
	$( document ).on( 'click', '.wpm2fa-enable', function( e ) {
		e.preventDefault();
		var userId = $( this ).data( 'user-id' );
		var nonce = $( this ).data( 'nonce' );
		var msg = $( '#wpm2fa-profile-message' );

		msg.addClass( 'success' ).removeClass( 'error' ).text( '...' ).show();

		$.ajax( {
			url: ajaxurl,
			type: 'POST',
			data: {
				action: 'wpm2fa_save_user_setting',
				user_id: userId,
				setting: 'enable',
				nonce: nonce
			},
			success: function( response ) {
				if ( response.success ) {
					msg.text( response.data.message ).fadeOut( 3000 );
					location.reload();
				} else {
					msg.removeClass( 'success' ).addClass( 'error' ).text( response.data.message );
				}
			},
			error: function() {
				msg.removeClass( 'success' ).addClass( 'error' ).text( wp_mail_2fa_admin.ajax_error );
			}
		} );
	} );

	// Disable 2FA.
	$( document ).on( 'click', '.wpm2fa-disable', function( e ) {
		e.preventDefault();
		var userId = $( this ).data( 'user-id' );
		var nonce = $( this ).data( 'nonce' );
		var msg = $( '#wpm2fa-profile-message' );

		if ( ! confirm( wp_mail_2fa_admin.disable_confirm ) ) {
			return;
		}

		msg.addClass( 'success' ).removeClass( 'error' ).text( '...' ).show();

		$.ajax( {
			url: ajaxurl,
			type: 'POST',
			data: {
				action: 'wpm2fa_disable_2fa',
				user_id: userId,
				nonce: nonce
			},
			success: function( response ) {
				if ( response.success ) {
					msg.text( response.data.message ).fadeOut( 3000 );
					location.reload();
				} else {
					msg.removeClass( 'success' ).addClass( 'error' ).text( response.data.message );
				}
			}
		} );
	} );

	// Send test email.
	$( document ).on( 'click', '.wpm2fa-send-test', function( e ) {
		e.preventDefault();
		var userId = $( this ).data( 'user-id' );
		var nonce = $( this ).data( 'nonce' );
		var msg = $( '#wpm2fa-profile-message' );

		msg.addClass( 'success' ).removeClass( 'error' ).text( '...' ).show();

		$.ajax( {
			url: ajaxurl,
			type: 'POST',
			data: {
				action: 'wpm2fa_send_test_email',
				user_id: userId,
				nonce: nonce
			},
			success: function( response ) {
				if ( response.success ) {
					msg.text( response.data.message ).fadeOut( 3000 );
				} else {
					msg.removeClass( 'success' ).addClass( 'error' ).text( response.data.message );
				}
			}
		} );
	} );

} )( jQuery );
