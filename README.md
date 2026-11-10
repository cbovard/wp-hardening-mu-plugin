# WP Hardening MU-Plugin

A must-use WordPress plugin that applies the **principle of least privilege** to a stock WordPress install. It denies anonymous REST API access by default, stops username enumeration, blocks XML-RPC, removes discovery metadata, and sends basic security headers.

Logged-in users are not affected. The block editor, Yoast and other admin tools that use the REST API keep working as normal.

---

## Why this exists

Out of the box, WordPress exposes much more to anonymous visitors than most sites ever use.

The principle of least privilege says a system should grant only the access each user actually needs, and nothing more. A typical brochure site, restaurant, agency site or small business blog never needs an anonymous visitor to:

- list every REST route, namespace and plugin endpoint installed on the site
- fetch a list of the site's authors and their login-style usernames
- call XML-RPC methods, including `system.multicall`, which can test hundreds of passwords in a single request
- resolve `/?author=1` to a username through a redirect
- read a users sitemap
- see the exact WordPress version in the page source

All of these are on by default, for every site.

### The REST API is always on, and that was a deliberate decision

In 2017, [Trac ticket #39806](https://core.trac.wordpress.org/ticket/39806), *"Disable REST API by default, making it opt-in rather than always-on"*, proposed letting site owners choose:

- a Settings toggle to turn the REST API on, similar to the "discourage search engines" option
- a `WP_REST_API` constant in `wp-config.php`
- themes and plugins declaring when they depend on the API

The thread shows why people were asking. The WordPress 4.7 REST API content-injection vulnerability had just been exploited, and commenters described client sites that didn't use the REST API being defaced through it within days. Others asked why the `/wp-json/wp/v2/users` endpoint hands anyone a list of usernames.

Core's response was that the REST API is core functionality, not an optional layer. Locking it down was declared "plugin territory," and the ticket was [closed as wontfix in comment 20](https://core.trac.wordpress.org/ticket/39806#comment:20) with the summary that *"the default for the REST API is _on_."* The recommended approach from core contributors was to **restrict it to authenticated users** with a plugin, which is exactly what this plugin does.

### Nine years later, people still ask

The same question keeps coming back. In a 2024 support thread, [*"wp-json exposing my website content"*](https://wordpress.org/support/topic/wp-json-exposing-my-website-content/), a site owner found that `/wp-json/wp/v2/users` listed their users and `/wp-json/wp/v2/posts?per_page=100` returned their content in bulk. The forum answer was that the API is working as designed and that they should search for a plugin. The thread was closed unresolved.

### Why it matters more than "the content is public anyway"

The common reply is that the REST API only exposes what is already public. That misses two things:

1. **Usernames are half of a login.** Author slugs from `/wp-json/wp/v2/users`, `/?author=N` redirects and the users sitemap give attackers the username for brute-force and credential-stuffing attacks.
2. **Every plugin's REST routes are reachable by anyone.** Many plugins register routes with permissive or missing permission checks. When one of them has a vulnerability, the endpoint is already open to the whole internet. A site that never needed anonymous REST access is exposed to bugs in code it never uses.

Least privilege turns that around: anonymous access is closed by default, and you open only what a public feature actually needs.

---

## What it does

| Area | Default WordPress | With this plugin |
| --- | --- | --- |
| REST API (anonymous) | All routes open, including the `/wp-json/` index and `/wp/v2/users` | **404** for every anonymous REST request unless the route is allowlisted |
| REST API (logged in) | Normal capability checks | Unchanged |
| REST discovery | `<link rel="https://api.w.org/">` and a `Link:` header on every page | Removed |
| oEmbed | Discovery links, `wp-embed.js` and `/oembed/1.0/*` routes | Removed |
| XML-RPC | Enabled, including `system.multicall` | **403** for every request to `xmlrpc.php` |
| Author enumeration | `/?author=1` redirects to `/author/<username>/` | **404**, before the redirect can leak the name |
| Users sitemap | `/wp-sitemap-users-1.xml` | Removed |
| Version / legacy metadata | Generator tag, RSD and WLW manifest links | Removed |
| RSS / Atom feeds | On | **404** (see "Before you install") |
| Security headers | None on the front end | HSTS (1 week, HTTPS only), `X-Frame-Options: SAMEORIGIN`, `Content-Security-Policy: frame-ancestors 'self'`, `Cross-Origin-Opener-Policy: same-origin` |

### How the REST block works

The plugin hooks `rest_authentication_errors` at priority 1 and returns WordPress's own `rest_no_route` 404 for anonymous requests. A blocked route looks exactly like a route that doesn't exist.

- It reads the route from `$wp->query_vars['rest_route']`, the same value core uses, so `/wp-json/...`, `/wp-json` and `/?rest_route=/...` are all covered.
- It never overrides an existing authentication result or error.
- `admin-ajax.php` and form plugins that post to the page itself (such as Gravity Forms) are not affected.

---

## Installation

1. Copy `modern-wp-security.php` to `wp-content/mu-plugins/`. Create the folder if it doesn't exist.
2. That's it. Must-use plugins load automatically and can't be deactivated from the admin.

Test while logged out (or in a private window):

```bash
curl -s https://example.com/wp-json/ | head -c 200          # → {"code":"rest_no_route",...}
curl -s https://example.com/wp-json/wp/v2/users              # → 404
curl -sI "https://example.com/?author=1" | head -1           # → 404
curl -s -o /dev/null -w "%{http_code}\n" https://example.com/xmlrpc.php   # → 403
```

---

## Before you install

This plugin is strict on purpose. Check these on each site first:

- **Plugins that need anonymous REST routes.** For example, the WooCommerce Store API / block checkout, Contact Form 7, some booking, search and headless setups. Allowlist their routes (below), or they'll break for logged-out visitors.
- **Jetpack, mobile apps or remote publishing** need XML-RPC. Remove section 6 if you use them.
- **RSS feeds** are disabled. Remove the `do_feed_*` hooks in section 5 if the site publishes a feed.
- **Embedding this site's posts elsewhere** (oEmbed) is disabled.
- **HSTS** is set to one week. Raise `max-age` once HTTPS is confirmed everywhere.

### Allowlisting a public REST route

Add anchored regex patterns with the `modern_wp_security_public_rest_route_patterns` filter, for example in another mu-plugin:

```php
add_filter( 'modern_wp_security_public_rest_route_patterns', function ( $patterns ) {
	$patterns[] = '#^/wc/store/v1(/|$)#';           // WooCommerce Store API (block cart/checkout)
	$patterns[] = '#^/contact-form-7/v1/contact-forms/\d+/feedback$#'; // Contact Form 7
	return $patterns;
} );
```

---

## Not a substitute for

Updates, strong passwords and 2FA, least-privilege user roles, file permissions, backups, and a web application firewall. This plugin reduces the attack surface; it doesn't clean an infected site.

---

## License

[GPL-2.0-or-later](LICENSE), the same license as WordPress.

## Author

Chris Bovard: WordPress and Drupal fixes, security and DevOps. [chrisbovard.com](https://www.chrisbovard.com) · [GitHub](https://github.com/cbovard)
