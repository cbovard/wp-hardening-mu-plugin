<?php
/**
 * Plugin Name: Modern WP Security
 * Description: Denies anonymous WordPress REST API access by default (this site has no plugin that
 *              needs a public REST route - no WooCommerce storefront, no Contact Form 7). Also removes
 *              REST/oEmbed/legacy discovery metadata and blocks feed and author-enumeration probes.
 * Version:     1.0.0
 * Author:      Modern WP Security
 * Text Domain: modern-wp-security
 *
 * Core policy: deny anonymous REST access by default. This site has no plugin that
 * requires a public/anonymous REST route - Gravity Forms submits via a direct POST/iframe to the
 * page itself, not through /wp-json/, so it needs nothing on the allowlist. The allowlist mechanism
 * is kept (via the modern_wp_security_public_rest_route_patterns filter) in case a future plugin
 * needs one, but ships empty by default. Authenticated WordPress users (cookie auth, Application
 * Passwords, etc.) are never affected by the anonymous deny-by-default logic below; WordPress's
 * normal per-endpoint capability checks continue to apply to them exactly as before.
 *
 * @package Modern_WP_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

/**
 * =============================================================================
 * 1. REST API: deny anonymous requests by default, allowlist public routes.
 * =============================================================================
 */

/**
 * Determine the REST route being requested, regardless of URL form.
 *
 * Reads `$wp->query_vars['rest_route']` - the exact same value WordPress core's
 * own rest_api_loaded() uses to decide whether the current request is a REST
 * request at all (see wp-includes/rest-api.php). Core's rewrite rules populate
 * this for the pretty-permalink form (/wp-json/..., including the bare
 * /wp-json root with no trailing slash) and WordPress's public-query-var
 * handling populates it from $_GET for the plain-permalink form
 * (/?rest_route=/...) too, so a single read here always agrees with core on
 * what counts as a REST request - no separate URL parsing of our own to get
 * subtly wrong (e.g. a missing trailing slash).
 *
 * @return string The requested REST route (e.g. "/wc/store/v1/cart"), or an empty
 *                string if this is not a REST request.
 */
function modern_wp_security_get_current_rest_route() {
	global $wp;

	if ( empty( $wp->query_vars['rest_route'] ) || ! is_string( $wp->query_vars['rest_route'] ) ) {
		return '';
	}

	return '/' . ltrim( $wp->query_vars['rest_route'], '/' );
}

/**
 * Whether a REST route is on the public (anonymous-accessible) allowlist.
 *
 * Deny-by-default: only routes matching one of these anchored patterns are
 * reachable without authentication. Everything else is a 404 for anonymous
 * requests (see modern_wp_security_rest_authentication_errors()).
 *
 * Empty by default on this site: there's no WooCommerce storefront and no
 * Contact Form 7, and nothing else here needs an anonymous REST route (see
 * the file header). Add a pattern via the
 * modern_wp_security_public_rest_route_patterns filter below if a future
 * plugin needs one.
 *
 * @param string $route The REST route, e.g. "/wc/store/v1/cart".
 * @return bool True if the route is approved for anonymous access.
 */
function modern_wp_security_is_public_rest_route( $route ) {
	$route = '/' . ltrim( (string) $route, '/' );

	$public_route_patterns = array();

	/**
	 * Filter the anonymously-accessible REST route patterns.
	 *
	 * Patterns must be anchored regular expressions matched against the route
	 * (e.g. "/wc/store/v1/cart"), not the full request URL.
	 *
	 * @param string[] $public_route_patterns Anchored regex patterns.
	 */
	$public_route_patterns = apply_filters( 'modern_wp_security_public_rest_route_patterns', $public_route_patterns );

	foreach ( $public_route_patterns as $pattern ) {
		if ( preg_match( $pattern, $route ) ) {
			return true;
		}
	}

	return false;
}

/**
 * Build the 404 error returned for disallowed anonymous REST requests.
 *
 * Matches WordPress's own "no route" error shape so behaviour is
 * indistinguishable from a route that simply doesn't exist.
 *
 * @return WP_Error
 */
function modern_wp_security_rest_404_error() {
	return new WP_Error(
		'rest_no_route',
		__( 'No route was found matching the URL and request method.', 'modern-wp-security' ),
		array( 'status' => 404 )
	);
}

/**
 * Deny anonymous REST API requests by default; allowlist public storefront and
 * form routes; leave authenticated requests and existing auth errors untouched.
 *
 * Hooked very early (priority 1) on the supported `rest_authentication_errors`
 * filter, before any other authentication provider gets a chance to turn a
 * still-null result into `true`. Running first is safe: WordPress core's own
 * auth checks start by checking "if the result isn't empty, return it
 * unchanged" (see rest_cookie_check_errors(), rest_application_password_check_errors()),
 * so a WP_Error we return here is preserved untouched all the way through the
 * rest of the filter chain. (This site has no WooCommerce, but the early
 * priority is kept in case a future plugin's authentication provider is added
 * at the default priority 10 and would otherwise short-circuit this check.)
 *
 * This also covers the anonymous REST root index (/wp-json/ and
 * /?rest_route=/) and any namespace index (e.g. /wp-json/wp/v2): neither
 * matches an allowlist pattern, so both fall through to the 404 below,
 * which prevents anonymous discovery of routes, capabilities, and
 * Application Password support advertised in the root index response.
 *
 * @param WP_Error|null|true $errors WP_Error if a previous auth check failed,
 *                                   true if explicitly authenticated, null otherwise.
 * @return WP_Error|null|true
 */
function modern_wp_security_rest_authentication_errors( $errors ) {
	// Preserve any existing authentication error/result from WordPress core or
	// another authentication provider - we only ever add a *new* denial, never
	// override or hide an existing one.
	if ( null !== $errors ) {
		return $errors;
	}

	// Authenticated WordPress users (cookie auth, Application Passwords, etc.)
	// are left completely alone here. WordPress's normal per-endpoint
	// capability checks (permission_callback) continue to run for them exactly
	// as if this plugin were not active - this includes editors and
	// administrators using the block editor, Yoast, and Simple History's REST
	// endpoints.
	if ( is_user_logged_in() ) {
		return $errors;
	}

	$route = modern_wp_security_get_current_rest_route();

	// Not a REST request we recognise (route couldn't be determined) - leave
	// WordPress to handle it normally.
	if ( '' === $route ) {
		return $errors;
	}

	if ( modern_wp_security_is_public_rest_route( $route ) ) {
		return $errors;
	}

	// Deny by default: anonymous request to a non-allowlisted route (including
	// the root index, any namespace index, and the WP users endpoint) is a 404.
	return modern_wp_security_rest_404_error();
}
add_filter( 'rest_authentication_errors', 'modern_wp_security_rest_authentication_errors', 1 );

/**
 * =============================================================================
 * 2. REST discovery removal (defence in depth - the routes are already 404s
 *    for anonymous users above, but the discovery metadata itself is also
 *    stripped so it's never advertised to logged-out visitors).
 * =============================================================================
 */

// Remove <link rel="https://api.w.org/" ...> from wp_head() on every page.
remove_action( 'wp_head', 'rest_output_link_wp_head' );

// Remove the REST "Link:" HTTP response header sent on every front-end request.
remove_action( 'template_redirect', 'rest_output_link_header', 11 );

/**
 * =============================================================================
 * 3. oEmbed removal.
 * =============================================================================
 */

// Remove the JSON and XML oEmbed discovery <link> tags from wp_head().
add_filter( 'oembed_discovery_links', '__return_empty_array' );
remove_action( 'wp_head', 'wp_oembed_add_discovery_links' ); // Defence in depth.

// Remove the oEmbed host <script> (wp-embed.js) used for embedding this site elsewhere.
remove_action( 'wp_head', 'wp_oembed_add_host_js' );

// Unregister the oEmbed REST routes entirely: /wp-json/oembed/1.0/embed and /proxy.
remove_action( 'rest_api_init', 'wp_oembed_register_route' );

/**
 * =============================================================================
 * 4. Legacy metadata removal.
 * =============================================================================
 */

// Remove the RSD (Really Simple Discovery) link, i.e. <link rel="EditURI" ...>
// pointing at xmlrpc.php?rsd.
remove_action( 'wp_head', 'rsd_link' );

// Remove the Windows Live Writer manifest link.
remove_action( 'wp_head', 'wlwmanifest_link' );

// Remove the WordPress version "generator" meta tag from wp_head() and strip it
// from feeds/other contexts that also request it.
remove_action( 'wp_head', 'wp_generator' );
add_filter( 'the_generator', '__return_empty_string' );

// Remove feed discovery <link> tags from wp_head().
remove_action( 'wp_head', 'feed_links', 2 );
remove_action( 'wp_head', 'feed_links_extra', 3 );

/**
 * =============================================================================
 * 5. Additional hardening.
 * =============================================================================
 */

/**
 * Disable RSS, RDF, and Atom feeds by returning a 404 instead of feed output.
 *
 * Hooked at priority 1 so it runs before (and short-circuits via wp_die())
 * WordPress core's default feed-rendering callback on the same hook. This
 * covers post feeds and comment feeds alike, since both fire the same
 * do_feed_{$type} action.
 */
function modern_wp_security_disable_feed() {
	wp_die(
		esc_html__( 'No feed available, please visit the homepage.', 'modern-wp-security' ),
		'',
		array( 'response' => 404 )
	);
}
add_action( 'do_feed_rdf', 'modern_wp_security_disable_feed', 1 );
add_action( 'do_feed_rss', 'modern_wp_security_disable_feed', 1 );
add_action( 'do_feed_rss2', 'modern_wp_security_disable_feed', 1 );
add_action( 'do_feed_atom', 'modern_wp_security_disable_feed', 1 );

/**
 * Remove the WordPress core "users" sitemap provider (/wp-sitemap-users-*.xml).
 *
 * @param WP_Sitemaps_Provider|false $provider The registered provider instance, or false.
 * @param string                     $name     The provider name being registered.
 * @return WP_Sitemaps_Provider|false
 */
function modern_wp_security_remove_users_sitemap( $provider, $name ) {
	if ( 'users' === $name ) {
		return false;
	}

	return $provider;
}
add_filter( 'wp_sitemaps_add_provider', 'modern_wp_security_remove_users_sitemap', 10, 2 );

/**
 * Force the current request to a 404 by resetting the main query's flags.
 *
 * WordPress's own template loader then selects and renders the theme's 404
 * template as usual, so no exit/redirect is needed here.
 */
function modern_wp_security_force_404() {
	global $wp_query;

	$wp_query->set_404();
	status_header( 404 );
	nocache_headers();
}

/**
 * Block author archives (/author/{name}/) and ?author={id} enumeration requests.
 *
 * Hooked at priority 0 - before WordPress core's redirect_canonical() (priority
 * 10) - so that a request such as /?author=1 is turned into a 404 before core
 * can resolve and redirect it to the canonical /author/{username}/ URL, which
 * would otherwise leak the username via the redirect's Location header.
 * set_404() clears the is_author() flag as part of resetting query flags, so
 * the later redirect_canonical() call sees a 404 request and does not act.
 */
function modern_wp_security_block_author_enumeration() {
	if ( is_author() || isset( $_GET['author'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		modern_wp_security_force_404();
	}
}
add_action( 'template_redirect', 'modern_wp_security_block_author_enumeration', 0 );

/*
 * Note: public REST user enumeration (/wp-json/wp/v2/users and
 * /wp-json/wp/v2/users/{id}) is already blocked for anonymous requests by the
 * deny-by-default policy in section 1 above - neither route is on the public
 * allowlist (which is empty on this site). Nothing else is required here.
 *
 * Note: this deny-by-default policy only affects the WordPress REST API. It
 * does not touch wp-admin/admin-ajax.php or Gravity Forms' front-end
 * submission (posted directly to the page/iframe, not through /wp-json/),
 * both of which remain fully reachable for logged-out visitors.
 */

/**
 * =============================================================================
 * 6. XML-RPC: block entirely.
 * =============================================================================
 */

/**
 * Hard-block every request to xmlrpc.php, regardless of the XML-RPC method
 * being called.
 *
 * This site has no Jetpack, no remote-publishing client (e.g. desktop/mobile
 * blogging apps), and doesn't accept pingbacks, so nothing legitimate needs
 * this endpoint. Deliberately not using the common
 * `add_filter( 'xmlrpc_enabled', '__return_false' )` soft-disable: that only
 * makes a handful of methods (mainly pingback) return a fault - it does not
 * stop `system.multicall` from being used to test many username/password
 * combinations against `wp.getUsersBlogs` in a single request, which is the
 * actual brute-force vector this is meant to close.
 *
 * XMLRPC_REQUEST is defined by WordPress core's xmlrpc.php before it loads
 * wp-load.php (and therefore this mu-plugin), so this runs and exits before
 * wp_xmlrpc_server is ever instantiated - no XML-RPC method, including
 * introspection ones like system.listMethods, ever executes.
 */
if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
	status_header( 403 );
	nocache_headers();
	exit( 'XML-RPC services are disabled on this site.' );
}

/**
 * =============================================================================
 * 7. Security response headers.
 * =============================================================================
 */

/**
 * Send security headers on front-end responses.
 *
 * - Strict-Transport-Security: HTTPS only (sent only over HTTPS). Starts at one
 *   week; raise max-age once HTTPS is confirmed stable everywhere. No
 *   includeSubDomains, so other subdomains of the live domain aren't affected.
 * - X-Frame-Options + CSP frame-ancestors: no framing by other sites
 *   (clickjacking). The CSP header carries only frame-ancestors, so it doesn't
 *   restrict scripts or styles.
 * - Cross-Origin-Opener-Policy: isolates this site's window from cross-origin
 *   pop-ups.
 *
 * wp-admin and wp-login already get X-Frame-Options from WordPress core.
 */
function modern_wp_security_send_headers() {
	if ( headers_sent() ) {
		return;
	}

	if ( is_ssl() ) {
		header( 'Strict-Transport-Security: max-age=604800' );
	}

	header( 'X-Frame-Options: SAMEORIGIN' );
	header( "Content-Security-Policy: frame-ancestors 'self'" );
	header( 'Cross-Origin-Opener-Policy: same-origin' );
}
add_action( 'send_headers', 'modern_wp_security_send_headers' );
