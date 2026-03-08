<?php
/**
 * Plugin Name: GT Storage
 * Description: GreyThing decentralized storage API — blobs, heads, inbox, and DID document serving.
 * Version: 1.0.0
 * Author: GreyThing
 * License: MIT
 * Requires PHP: 7.2
 */

if (!defined('ABSPATH')) exit;

define('GT_STORAGE_VERSION', '1.0.0');
define('GT_STORAGE_DIR', WP_CONTENT_DIR . '/gt-storage');

// Include classes
require_once __DIR__ . '/includes/class-gt-store.php';
require_once __DIR__ . '/includes/class-gt-auth.php';
require_once __DIR__ . '/includes/class-gt-router.php';
require_once __DIR__ . '/includes/class-gt-blobs.php';
require_once __DIR__ . '/includes/class-gt-heads.php';
require_once __DIR__ . '/includes/class-gt-inbox.php';
require_once __DIR__ . '/includes/class-gt-grants.php';
require_once __DIR__ . '/includes/class-gt-did-server.php';
require_once __DIR__ . '/includes/class-gt-register.php';

if (is_admin()) {
    require_once __DIR__ . '/admin/class-gt-admin.php';
}

// --- Activation ---

register_activation_hook(__FILE__, 'gt_storage_activate');

function gt_storage_activate() {
    // Create storage directory
    if (!file_exists(GT_STORAGE_DIR)) {
        wp_mkdir_p(GT_STORAGE_DIR);
    }
    if (!file_exists(GT_STORAGE_DIR . '/dids')) {
        wp_mkdir_p(GT_STORAGE_DIR . '/dids');
    }
    // Add .htaccess to deny direct access
    $htaccess = GT_STORAGE_DIR . '/.htaccess';
    if (!file_exists($htaccess)) {
        file_put_contents($htaccess, "Deny from all\n");
    }
    // Flush rewrite rules
    gt_storage_add_rewrite_rules();
    flush_rewrite_rules();
}

register_deactivation_hook(__FILE__, 'gt_storage_deactivate');

function gt_storage_deactivate() {
    flush_rewrite_rules();
}

// --- Rewrite rules ---

add_action('init', 'gt_storage_add_rewrite_rules');

function gt_storage_add_rewrite_rules() {
    // Catch /gt/v1/... requests
    add_rewrite_rule('^gt/v1/(.*)$', 'index.php?gt_api_path=$1', 'top');
    // Catch /.well-known/did.json
    add_rewrite_rule('^\.well-known/did\.json$', 'index.php?gt_did_root=1', 'top');
    // Catch /{path}/did.json for sub-path DIDs
    add_rewrite_rule('^(.+)/did\.json$', 'index.php?gt_did_path=$1', 'top');
    // Registration page
    add_rewrite_rule('^gt-register/?$', 'index.php?gt_register_page=1', 'top');
    // Dashboard page
    add_rewrite_rule('^gt-dashboard/?$', 'index.php?gt_dashboard_page=1', 'top');
}

add_filter('query_vars', 'gt_storage_query_vars');

function gt_storage_query_vars($vars) {
    $vars[] = 'gt_api_path';
    $vars[] = 'gt_did_root';
    $vars[] = 'gt_did_path';
    $vars[] = 'gt_register_page';
    $vars[] = 'gt_dashboard_page';
    return $vars;
}

// --- Request handling ---
// Use init hook (early) to intercept GT requests before WordPress routing.
// This is more reliable than parse_request for non-GET methods (POST, PUT, DELETE).

add_action('init', 'gt_storage_early_intercept', 1);

function gt_storage_early_intercept() {
    $uri = $_SERVER['REQUEST_URI'];
    // Strip query string
    $path = parse_url($uri, PHP_URL_PATH);
    // Remove leading slash
    $path = ltrim($path, '/');

    // /gt/v1/...
    if (strpos($path, 'gt/v1/') === 0) {
        $api_path = substr($path, 6); // strip "gt/v1/"
        gt_storage_dispatch_api($api_path);
        exit;
    }

    // /.well-known/did.json
    if ($path === '.well-known/did.json') {
        gt_storage_serve_did_root();
        exit;
    }

    // /{something}/did.json
    if (substr($path, -9) === '/did.json' && $path !== 'did.json') {
        $did_path = substr($path, 0, -9); // strip "/did.json"
        // Strip WordPress subdirectory prefix if installed in a subdirectory
        $did_path = ltrim($did_path, '/');
        gt_storage_serve_did_path($did_path);
        exit;
    }
    // Also match did.json at root without .well-known (edge case)
    if ($path === 'did.json') {
        gt_storage_serve_did_root();
        exit;
    }

    // /gt-register
    if ($path === 'gt-register' || $path === 'gt-register/') {
        gt_storage_serve_register_page();
        exit;
    }

    // /gt-dashboard
    if ($path === 'gt-dashboard' || $path === 'gt-dashboard/') {
        gt_storage_serve_dashboard_page();
        exit;
    }
}

function gt_storage_dispatch_api($path) {
    $store = new GT_Store(GT_STORAGE_DIR);
    $auth = new GT_Auth($store);
    $router = new GT_Router($store, $auth);
    $router->dispatch($path);
}

function gt_storage_serve_did_root() {
    $server = new GT_DID_Server();
    $server->serve_root();
}

function gt_storage_serve_did_path($path) {
    $server = new GT_DID_Server();
    $server->serve_path($path);
}

function gt_storage_serve_register_page() {
    $reg_enabled = get_option('gt_storage_registration', 'open');
    if ($reg_enabled === 'closed') {
        wp_die('Registration is currently closed.', 'Registration Closed', ['response' => 403]);
    }
    readfile(__DIR__ . '/pages/register.html');
}

function gt_storage_serve_dashboard_page() {
    readfile(__DIR__ . '/pages/dashboard.html');
}
