<?php
/**
 * GT_Admin — WordPress admin page for GT Storage settings.
 */
class GT_Admin {
    public function __construct() {
        add_action('admin_menu', [$this, 'add_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_post_gt_storage_add_did', [$this, 'handle_add_did']);
        add_action('admin_post_gt_storage_delete_did', [$this, 'handle_delete_did']);
        add_action('admin_post_gt_storage_update_registration', [$this, 'handle_update_registration']);
    }

    public function add_menu() {
        add_options_page(
            'GT Storage',
            'GT Storage',
            'manage_options',
            'gt-storage',
            [$this, 'render_page']
        );
    }

    public function register_settings() {
        register_setting('gt_storage_settings', 'gt_storage_dids');
    }

    public function render_page() {
        if (!current_user_can('manage_options')) return;

        $hosted_dids = get_option('gt_storage_dids', []);
        $storage_dir = GT_STORAGE_DIR;
        $dir_exists = is_dir($storage_dir);
        $dir_writable = $dir_exists && is_writable($storage_dir);

        // Calculate storage size
        $total_size = 0;
        if ($dir_exists) {
            $total_size = $this->dir_size($storage_dir);
        }

        // Count inbox items per DID
        $store = new GT_Store(GT_STORAGE_DIR);
        $inbox_counts = [];
        foreach ($hosted_dids as $entry) {
            if (isset($entry['did'])) {
                $keys = $store->list_keys($entry['did'] . '/inbox/');
                $inbox_counts[$entry['did']] = count($keys);
            }
        }

        include __DIR__ . '/settings-page.php';
    }

    public function handle_add_did() {
        if (!current_user_can('manage_options')) wp_die('Unauthorized');
        check_admin_referer('gt_storage_add_did');

        $did = sanitize_text_field($_POST['did'] ?? '');
        $path = sanitize_text_field($_POST['did_path'] ?? '');
        $did_json = wp_unslash($_POST['did_json'] ?? '');

        if (empty($did) || empty($did_json)) {
            wp_redirect(admin_url('options-general.php?page=gt-storage&error=missing_fields'));
            exit;
        }

        // Validate JSON
        $doc = json_decode($did_json, true);
        if (!is_array($doc)) {
            wp_redirect(admin_url('options-general.php?page=gt-storage&error=invalid_json'));
            exit;
        }

        // Generate filename from DID
        $filename = str_replace([':', '/'], '-', $did) . '.json';

        // Save DID document
        $store = new GT_Store(GT_STORAGE_DIR);
        if (!$store->put('dids/' . $filename, $did_json)) {
            wp_redirect(admin_url('options-general.php?page=gt-storage&error=write_failed'));
            exit;
        }

        // Create storage directories for this DID
        wp_mkdir_p(GT_STORAGE_DIR . '/' . $did . '/blobs/sha256');
        wp_mkdir_p(GT_STORAGE_DIR . '/' . $did . '/heads');
        wp_mkdir_p(GT_STORAGE_DIR . '/' . $did . '/inbox');

        // Add to hosted DIDs list
        $hosted_dids = get_option('gt_storage_dids', []);
        // Check if DID already exists
        foreach ($hosted_dids as $i => $entry) {
            if ($entry['did'] === $did) {
                $hosted_dids[$i] = ['did' => $did, 'path' => $path, 'file' => $filename];
                update_option('gt_storage_dids', $hosted_dids);
                wp_redirect(admin_url('options-general.php?page=gt-storage&updated=1'));
                exit;
            }
        }
        $hosted_dids[] = ['did' => $did, 'path' => $path, 'file' => $filename];
        update_option('gt_storage_dids', $hosted_dids);

        wp_redirect(admin_url('options-general.php?page=gt-storage&updated=1'));
        exit;
    }

    public function handle_update_registration() {
        if (!current_user_can('manage_options')) wp_die('Unauthorized');
        check_admin_referer('gt_storage_update_registration');

        $value = in_array($_POST['registration'] ?? '', ['open', 'closed']) ? $_POST['registration'] : 'open';
        update_option('gt_storage_registration', $value);

        wp_redirect(admin_url('options-general.php?page=gt-storage&updated=1'));
        exit;
    }

    public function handle_delete_did() {
        if (!current_user_can('manage_options')) wp_die('Unauthorized');
        check_admin_referer('gt_storage_delete_did');

        $did = sanitize_text_field($_POST['did'] ?? '');
        $hosted_dids = get_option('gt_storage_dids', []);
        $hosted_dids = array_values(array_filter($hosted_dids, function($e) use ($did) {
            return $e['did'] !== $did;
        }));
        update_option('gt_storage_dids', $hosted_dids);

        wp_redirect(admin_url('options-general.php?page=gt-storage&deleted=1'));
        exit;
    }

    private function dir_size($dir) {
        $size = 0;
        $items = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS));
        foreach ($items as $item) {
            if ($item->isFile()) {
                $size += $item->getSize();
            }
        }
        return $size;
    }
}

new GT_Admin();
