<?php
/**
 * GT_Blobs — Blob and blob metadata handlers.
 * Matches Go server.go blob handlers.
 */
class GT_Blobs {
    private $store;
    private $auth;
    private $grants;

    public function __construct($store, $auth, $grants) {
        $this->store = $store;
        $this->auth = $auth;
        $this->grants = $grants;
    }

    public function handle($method, $route) {
        if ($route['is_meta']) {
            switch ($method) {
                case 'GET':  $this->handle_meta_get($route); break;
                case 'PUT':  $this->handle_meta_put($route); break;
                default:     GT_Router::error_json(405, 'method_not_allowed', 'use GET or PUT'); break;
            }
        } else {
            switch ($method) {
                case 'GET':    $this->handle_get($route); break;
                case 'PUT':    $this->handle_put($route); break;
                case 'DELETE': $this->handle_delete($route); break;
                default:       GT_Router::error_json(405, 'method_not_allowed', 'use GET, PUT, or DELETE'); break;
            }
        }
    }

    // --- Blob key helpers ---

    private function blob_key($did, $hash) {
        return $did . '/blobs/sha256/' . $hash;
    }

    private function meta_key($did, $hash) {
        return $this->blob_key($did, $hash) . ':meta';
    }

    private function load_meta($did, $hash) {
        $data = $this->store->get($this->meta_key($did, $hash));
        if ($data === false) return null;
        return json_decode($data, true);
    }

    // --- GET blob ---

    private function handle_get($route) {
        $key = $this->blob_key($route['did'], $route['hash']);
        $data = $this->store->get($key);
        if ($data === false) {
            GT_Router::error_json(404, 'not_found', 'blob not found');
            return;
        }

        // Check ACL if meta exists
        $meta = $this->load_meta($route['did'], $route['hash']);
        if ($meta !== null && !$this->is_public_acl($meta)) {
            // Need auth
            $raw_body = '';
            $auth_result = $this->auth->authenticate($_SERVER['REQUEST_METHOD'], $_SERVER['REQUEST_URI'], $raw_body);
            $caller_did = isset($auth_result['did']) ? $auth_result['did'] : '';
            if (!$this->check_acl($meta, $route['did'], $caller_did)) {
                // ACL denied — try grant-based access
                $grant_caller = $caller_did;
                if (empty($grant_caller)) {
                    $grant_caller = isset($_SERVER['HTTP_X_GT_DID']) ? $_SERVER['HTTP_X_GT_DID'] : '';
                }
                if (!empty($grant_caller) && $this->grants->check_grant_access($route, $grant_caller)) {
                    // Grant access approved
                } else {
                    GT_Router::error_json(404, 'not_found', 'blob not found');
                    return;
                }
            }
        }

        header('Content-Type: application/octet-stream');
        header('Cache-Control: public, max-age=31536000, immutable');
        header('Content-Length: ' . strlen($data));
        echo $data;
    }

    // --- PUT blob ---

    private function handle_put($route) {
        $raw_body = file_get_contents('php://input');
        $auth_result = $this->auth->authenticate('PUT', '/gt/v1/' . $route['did'] . '/blobs/sha256/' . $route['hash'], $raw_body);
        if (isset($auth_result['error'])) {
            GT_Router::error_json(401, 'unauthorized', $auth_result['error']);
            return;
        }

        // Owner check
        if ($auth_result['did'] !== $route['did']) {
            GT_Router::error_json(403, 'forbidden', 'not the owner of this namespace');
            return;
        }

        // Verify hash matches body
        $actual_hash = hash('sha256', $raw_body);
        if ($actual_hash !== $route['hash']) {
            GT_Router::error_json(422, 'hash_mismatch', 'body hash does not match URL hash');
            return;
        }

        $key = $this->blob_key($route['did'], $route['hash']);

        // Check if already exists
        if ($this->store->exists($key)) {
            GT_Router::error_json(409, 'already_exists', 'blob already exists');
            return;
        }

        if (!$this->store->put($key, $raw_body)) {
            GT_Router::error_json(500, 'internal', 'failed to store blob');
            return;
        }

        http_response_code(201);
    }

    // --- DELETE blob ---

    private function handle_delete($route) {
        $raw_body = file_get_contents('php://input');
        $auth_result = $this->auth->authenticate('DELETE', '/gt/v1/' . $route['did'] . '/blobs/sha256/' . $route['hash'], $raw_body);
        if (isset($auth_result['error'])) {
            GT_Router::error_json(401, 'unauthorized', $auth_result['error']);
            return;
        }

        if ($auth_result['did'] !== $route['did']) {
            GT_Router::error_json(403, 'forbidden', 'not the owner of this namespace');
            return;
        }

        $key = $this->blob_key($route['did'], $route['hash']);
        if (!$this->store->exists($key)) {
            GT_Router::error_json(404, 'not_found', 'blob not found');
            return;
        }

        $this->store->delete($key);
        // Clean up meta if it exists
        $mk = $this->meta_key($route['did'], $route['hash']);
        $this->store->delete($mk); // ignore if not found

        http_response_code(204);
    }

    // --- GET meta ---

    private function handle_meta_get($route) {
        $raw_body = '';
        $auth_result = $this->auth->authenticate('GET', '/gt/v1/' . $route['did'] . '/blobs/sha256/' . $route['hash'] . ':meta', $raw_body);
        if (isset($auth_result['error'])) {
            GT_Router::error_json(401, 'unauthorized', $auth_result['error']);
            return;
        }

        if ($auth_result['did'] !== $route['did']) {
            GT_Router::error_json(403, 'forbidden', 'not the owner of this namespace');
            return;
        }

        $meta = $this->load_meta($route['did'], $route['hash']);
        if ($meta === null) {
            GT_Router::error_json(404, 'not_found', 'meta not found');
            return;
        }

        header('Content-Type: application/json');
        echo json_encode($meta);
    }

    // --- PUT meta ---

    private function handle_meta_put($route) {
        $raw_body = file_get_contents('php://input');
        $auth_result = $this->auth->authenticate('PUT', '/gt/v1/' . $route['did'] . '/blobs/sha256/' . $route['hash'] . ':meta', $raw_body);
        if (isset($auth_result['error'])) {
            GT_Router::error_json(401, 'unauthorized', $auth_result['error']);
            return;
        }

        if ($auth_result['did'] !== $route['did']) {
            GT_Router::error_json(403, 'forbidden', 'not the owner of this namespace');
            return;
        }

        // Blob must exist
        $bk = $this->blob_key($route['did'], $route['hash']);
        if (!$this->store->exists($bk)) {
            GT_Router::error_json(404, 'not_found', 'blob not found');
            return;
        }

        $meta = json_decode($raw_body, true);
        if (!is_array($meta)) {
            GT_Router::error_json(400, 'bad_request', 'invalid JSON body');
            return;
        }

        $now = gmdate('Y-m-d\TH:i:s\Z');

        // Check if meta already exists (update vs create)
        $existing = $this->load_meta($route['did'], $route['hash']);
        if ($existing !== null) {
            $meta['createdAt'] = $existing['createdAt'];
            $meta['updatedAt'] = $now;
        } else {
            $meta['createdAt'] = $now;
        }

        $mk = $this->meta_key($route['did'], $route['hash']);
        // Delete old if exists, then put new
        $this->store->delete($mk);
        if (!$this->store->put($mk, json_encode($meta))) {
            GT_Router::error_json(500, 'internal', 'failed to store meta');
            return;
        }

        header('Content-Type: application/json');
        echo json_encode($meta);
    }

    // --- ACL helpers ---

    private function is_public_acl($meta) {
        if (!isset($meta['acl']) || !is_array($meta['acl'])) return true; // no ACL = public
        return in_array('*', $meta['acl']);
    }

    private function check_acl($meta, $owner_did, $caller_did) {
        if ($caller_did === $owner_did) return true;
        if (!isset($meta['acl']) || !is_array($meta['acl'])) return true;
        foreach ($meta['acl'] as $entry) {
            if ($entry === '*' || $entry === $caller_did) return true;
        }
        return false;
    }
}
