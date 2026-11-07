=== WP Mail 2FA ===
Contributors: arena
Tags: two-factor, 2fa, authentication, email, security
Requires at least: 5.8
Tested up to: 6.7
Requires PHP: 7.2
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Two-factor authentication via email for WordPress. Users receive a one-time code on login.

== Description ==

WP Mail 2FA adds email-based two-factor authentication to WordPress.

**How it works:**

1. User enters their username and password on the login page.
2. If 2FA is enabled (per-user or enforced site-wide), the plugin blocks the login and shows a verification form.
3. A 6-digit code is sent to the user's registered email address.
4. User enters the code to complete authentication.
5. User is logged in.

**Features:**

* **Email verification** — 6-digit codes sent via wp_mail.
* **Configurable code length** — 4 to 8 digits.
* **Configurable code expiry** — 1 to 60 minutes.
* **Resend delay** — prevents spamming the resend endpoint.
* **Per-user enable/disable** — users can manage their own 2FA in profile.
* **Site-wide enforcement** — require 2FA for all users or specific roles.
* **Grace period** — configurable delay before enforcing 2FA on new users.
* **Setup wizard** — guided initial configuration.
* **REST API** — programmatic access to send codes and validate.
* **Test email** — admin can send test email from settings/profile.
* **White labeling** — customizable plugin name and email sender.
* **No external dependencies** — pure WordPress, uses wp_mail.

== Installation ==

1. Upload the `wp-mail-2fa` folder to `/wp-content/plugins/`.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Go to Settings > WP Mail 2FA to configure.
4. Enable 2FA for users in their profile or enforce site-wide.

== Frequently Asked Questions ==

= What happens if a user doesn't receive the email? =

Check the spam folder. The plugin uses WordPress's standard `wp_mail()` function. If emails aren't arriving, configure an SMTP plugin like WP Mail SMTP. The admin can also use the "Send test email" button in the user profile.

= Can I require 2FA for all users? =

Yes. In Settings > WP Mail 2FA, enable "Require email 2FA" and configure enforcement options. A grace period can be set for users who haven't enabled 2FA yet.

= What if a user loses access to their email? =

The site administrator can disable 2FA for that user from their profile page. There are no backup codes in this plugin — it's email-only 2FA.

= Does the plugin send data to external servers? =

No. The plugin does not send any data to external servers. All code generation and validation happens locally. The only outbound connection is the email sent to the user's email address.

= Is there a REST API? =

Yes. The plugin exposes REST API endpoints under `wpm2fa/v1` for sending codes and validating them.

== Changelog ==

= 1.0.0 =
* Initial release.
* Email-based 2FA with configurable code length and expiry.
* Per-user enable/disable.
* Site-wide enforcement with role exemptions.
* Grace period for enforcement.
* REST API endpoints.
* Test email functionality.
* White labeling support.

== Upgrade Notice ==

= 1.0.0 =
Initial release.
