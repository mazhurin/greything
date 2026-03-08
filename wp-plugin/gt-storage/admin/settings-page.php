<?php if (!defined('ABSPATH')) exit; ?>
<div class="wrap">
    <h1>GT Storage Settings</h1>

    <?php if (isset($_GET['updated'])): ?>
        <div class="notice notice-success is-dismissible"><p>DID added/updated successfully.</p></div>
    <?php endif; ?>
    <?php if (isset($_GET['deleted'])): ?>
        <div class="notice notice-success is-dismissible"><p>DID removed.</p></div>
    <?php endif; ?>
    <?php if (isset($_GET['error'])): ?>
        <div class="notice notice-error is-dismissible"><p>Error: <?php echo esc_html($_GET['error']); ?></p></div>
    <?php endif; ?>

    <h2>Status</h2>
    <table class="widefat" style="max-width: 500px;">
        <tr><td>Storage directory</td><td><code><?php echo esc_html($storage_dir); ?></code></td></tr>
        <tr><td>Directory exists</td><td><?php echo $dir_exists ? 'Yes' : '<strong style="color:red;">No</strong>'; ?></td></tr>
        <tr><td>Writable</td><td><?php echo $dir_writable ? 'Yes' : '<strong style="color:red;">No</strong>'; ?></td></tr>
        <tr><td>Total storage size</td><td><?php echo size_format($total_size); ?></td></tr>
        <tr><td>PHP sodium</td><td><?php echo function_exists('sodium_crypto_sign_verify_detached') ? 'Available' : '<strong style="color:red;">Missing (PHP 7.2+ required)</strong>'; ?></td></tr>
    </table>

    <h2>Registration</h2>
    <?php $reg_enabled = get_option('gt_storage_registration', 'open'); ?>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
        <input type="hidden" name="action" value="gt_storage_update_registration">
        <?php wp_nonce_field('gt_storage_update_registration'); ?>
        <p>
            <label><input type="radio" name="registration" value="open" <?php checked($reg_enabled, 'open'); ?>> Open — anyone can register at <a href="<?php echo esc_url(home_url('/gt-register')); ?>">/gt-register</a></label><br>
            <label><input type="radio" name="registration" value="closed" <?php checked($reg_enabled, 'closed'); ?>> Closed — registration disabled</label>
        </p>
        <?php submit_button('Save', 'secondary'); ?>
    </form>

    <h2>Hosted DIDs</h2>
    <?php if (empty($hosted_dids)): ?>
        <p>No DIDs configured yet. Add one below.</p>
    <?php else: ?>
        <table class="widefat striped" style="max-width: 800px;">
            <thead>
                <tr>
                    <th>DID</th>
                    <th>URL Path</th>
                    <th>Inbox</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($hosted_dids as $entry): ?>
                <tr>
                    <td><code style="font-size: 12px;"><?php echo esc_html($entry['did']); ?></code></td>
                    <td>
                        <?php
                        $url_path = empty($entry['path'])
                            ? '/.well-known/did.json'
                            : '/' . $entry['path'] . '/did.json';
                        echo esc_html($url_path);
                        ?>
                    </td>
                    <td><?php echo isset($inbox_counts[$entry['did']]) ? intval($inbox_counts[$entry['did']]) : 0; ?> items</td>
                    <td>
                        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:inline;">
                            <input type="hidden" name="action" value="gt_storage_delete_did">
                            <input type="hidden" name="did" value="<?php echo esc_attr($entry['did']); ?>">
                            <?php wp_nonce_field('gt_storage_delete_did'); ?>
                            <button type="submit" class="button button-small" onclick="return confirm('Remove this DID?');">Remove</button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>

    <h2>Add DID</h2>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
        <input type="hidden" name="action" value="gt_storage_add_did">
        <?php wp_nonce_field('gt_storage_add_did'); ?>
        <table class="form-table" style="max-width: 700px;">
            <tr>
                <th><label for="did">DID</label></th>
                <td>
                    <input type="text" name="did" id="did" class="regular-text" placeholder="did:web:example.com" required>
                    <p class="description">The full DID identifier, e.g. <code>did:web:example.com</code> or <code>did:web:example.com:family:bob</code></p>
                </td>
            </tr>
            <tr>
                <th><label for="did_path">URL Path</label></th>
                <td>
                    <input type="text" name="did_path" id="did_path" class="regular-text" placeholder="">
                    <p class="description">
                        Leave empty for root (<code>/.well-known/did.json</code>).
                        For <code>did:web:example.com:family:bob</code>, enter <code>family/bob</code>.
                    </p>
                </td>
            </tr>
            <tr>
                <th><label for="did_json">DID Document (JSON)</label></th>
                <td>
                    <textarea name="did_json" id="did_json" rows="15" class="large-text code" required placeholder='Paste your did.json here'></textarea>
                    <p class="description">The complete DID document JSON. Generate keys with <code>gt-keygen</code> first.</p>
                </td>
            </tr>
        </table>
        <?php submit_button('Add DID'); ?>
    </form>
</div>
