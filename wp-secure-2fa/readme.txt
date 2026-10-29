=== WP Secure 2FA ===
Contributors: arena
Tags: two-factor, 2fa, authentication, security, totp, otp
Requires at least: 5.8
Tested up to: 6.7
Requires PHP: 7.2
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Adds Two-Factor Authentication to WordPress using TOTP, backup codes, and email verification.

== Description ==

WP Secure 2FA adds two-factor authentication to WordPress sites. It supports:

* **TOTP** (Time-based One-Time Password) — works with Google Authenticator, Authy, 1Password, etc.
* **Backup codes** — one-time use codes for emergency access.
* **Email verification** — 6-digit codes sent to user email.
* **Setup wizard** — guided initial configuration.
* **Per-user management** — users manage their own 2FA settings in profile.
* **Grace period** — configurable delay before enforcing 2FA on new users.
* **Enforcement** — require 2FA for all users or specific roles.
* **White labeling** — customizable plugin name.
* **REST API** — programmatic access to 2FA operations.
* **Admin toolbar indicator** — quick 2FA status check.

== Installation ==

1. Upload the `wp-secure-2fa` folder to `/wp-content/plugins/`.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Go to Settings > WP Secure 2FA to configure.
4. Follow the setup wizard for initial configuration.

== Frequently Asked Questions ==

= Which authenticator apps work with TOTP? =

Any app that supports RFC 6238 TOTP: Google Authenticator, Authy, 1Password, Bitwarden, Microsoft Authenticator, etc.

= What happens if I lose my phone? =

Use backup codes to regain access. Each backup code can only be used once. You can regenerate backup codes from your profile page.

= Can I require 2FA for all users? =

Yes. In Settings > WP Secure 2FA, enable "Require 2FA" and configure enforcement options. A grace period can be set for users who haven't configured 2FA yet.

= Does the plugin send data externally? =

No. The plugin does not send any data to external servers. All TOTP generation and verification happens locally.

= Is there a REST API? =

Yes. The plugin exposes REST API endpoints under `wps2fa/v1` for programmatic access to 2FA operations.

== Changelog ==

= 1.0.0 =
* Initial release.
* TOTP support with configurable period, digits, and algorithm.
* Backup codes generation and validation.
* Email verification method.
* Setup wizard.
* Per-user profile management.
* Grace period for enforcement.
* REST API endpoints.
* Admin toolbar status indicator.
* White labeling support.

== Upgrade Notice ==

= 1.0.0 =
Initial release.
