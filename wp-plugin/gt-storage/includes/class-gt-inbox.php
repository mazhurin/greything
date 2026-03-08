<?php
/**
 * GT_Inbox — Inbox handlers for E2EE private messages.
 * Matches Go inbox.go.
 */
class GT_Inbox {
    private $store;
    private $auth;

    const MAX_ITEM_SIZE = 65536; // 64 KB
    const MAX_ITEMS = 200;

    public function __construct($store, $auth) {
        $this->store = $store;
        $this->auth = $auth;
    }

    public function handle($method, $route) {
        if (empty($route['inbox_item_id'])) {
            // /gt/v1/{did}/inbox
            switch ($method) {
                case 'POST': $this->handle_post($route); break;
                case 'GET':  $this->handle_list($route); break;
                default:     GT_Router::error_json(405, 'method_not_allowed', 'use GET or POST'); break;
            }
        } else {
            // /gt/v1/{did}/inbox/{id}
            switch ($method) {
                case 'GET':    $this->handle_get($route); break;
                case 'DELETE': $this->handle_delete($route); break;
                default:       GT_Router::error_json(405, 'method_not_allowed', 'use GET or DELETE'); break;
            }
        }
    }

    private function inbox_prefix($did) {
        return $did . '/inbox/';
    }

    private function inbox_key($did, $item_id) {
        return $did . '/inbox/' . $item_id;
    }

    // --- POST (anonymous drop, no auth) ---

    private function handle_post($route) {
        $body = file_get_contents('php://input');

        if (strlen($body) > self::MAX_ITEM_SIZE) {
            GT_Router::error_json(413, 'too_large', 'max inbox item size is 64KB');
            return;
        }
        if (strlen($body) === 0) {
            GT_Router::error_json(400, 'bad_request', 'empty body');
            return;
        }

        // Validate JSON with type InboxCiphertextV1
        $envelope = json_decode($body, true);
        if (!is_array($envelope)) {
            GT_Router::error_json(400, 'bad_request', 'body must be valid JSON');
            return;
        }
        if (!isset($envelope['type']) || $envelope['type'] !== 'InboxCiphertextV1') {
            GT_Router::error_json(400, 'bad_request', 'type must be InboxCiphertextV1');
            return;
        }

        // Check inbox size limit
        $prefix = $this->inbox_prefix($route['did']);
        $existing = $this->store->list_keys($prefix);
        if (count($existing) >= self::MAX_ITEMS) {
            GT_Router::error_json(409, 'inbox_full', 'recipient inbox is full');
            return;
        }

        // Generate server-assigned ID: timestamp + random
        $item_id = gmdate('Ymd\THis\Z') . '-' . bin2hex(random_bytes(4));

        $key = $this->inbox_key($route['did'], $item_id);
        if (!$this->store->put($key, $body)) {
            GT_Router::error_json(500, 'internal', 'failed to store inbox item');
            return;
        }

        http_response_code(201);
        header('Content-Type: application/json');
        echo json_encode(['id' => $item_id]);
    }

    // --- GET list (auth required, owner only) ---

    private function handle_list($route) {
        $raw_body = '';
        $auth_result = $this->auth->authenticate('GET', '/gt/v1/' . $route['did'] . '/inbox', $raw_body);
        if (isset($auth_result['error'])) {
            GT_Router::error_json(401, 'unauthorized', $auth_result['error']);
            return;
        }
        if ($auth_result['did'] !== $route['did']) {
            GT_Router::error_json(403, 'forbidden', 'not the owner of this namespace');
            return;
        }

        $prefix = $this->inbox_prefix($route['did']);
        $keys = $this->store->list_keys($prefix);

        $entries = [];
        foreach ($keys as $k) {
            $id = str_replace($prefix, '', $k);
            // Skip nested paths or temp files
            if (strpos($id, '/') !== false || strpos($id, '.tmp') !== false) continue;
            $data = $this->store->get($k);
            if ($data === false) continue;
            $entries[] = ['id' => $id, 'size' => strlen($data)];
        }

        header('Content-Type: application/json');
        echo json_encode($entries);
    }

    // --- GET item (auth required, owner only) ---

    private function handle_get($route) {
        $raw_body = '';
        $auth_result = $this->auth->authenticate('GET', '/gt/v1/' . $route['did'] . '/inbox/' . $route['inbox_item_id'], $raw_body);
        if (isset($auth_result['error'])) {
            GT_Router::error_json(401, 'unauthorized', $auth_result['error']);
            return;
        }
        if ($auth_result['did'] !== $route['did']) {
            GT_Router::error_json(403, 'forbidden', 'not the owner of this namespace');
            return;
        }

        $key = $this->inbox_key($route['did'], $route['inbox_item_id']);
        $data = $this->store->get($key);
        if ($data === false) {
            GT_Router::error_json(404, 'not_found', 'inbox item not found');
            return;
        }

        header('Content-Type: application/json');
        echo $data;
    }

    // --- DELETE item (auth required, owner only) ---

    private function handle_delete($route) {
        $raw_body = file_get_contents('php://input');
        $auth_result = $this->auth->authenticate('DELETE', '/gt/v1/' . $route['did'] . '/inbox/' . $route['inbox_item_id'], $raw_body);
        if (isset($auth_result['error'])) {
            GT_Router::error_json(401, 'unauthorized', $auth_result['error']);
            return;
        }
        if ($auth_result['did'] !== $route['did']) {
            GT_Router::error_json(403, 'forbidden', 'not the owner of this namespace');
            return;
        }

        $key = $this->inbox_key($route['did'], $route['inbox_item_id']);
        if (!$this->store->exists($key)) {
            GT_Router::error_json(404, 'not_found', 'inbox item not found');
            return;
        }

        $this->store->delete($key);
        http_response_code(204);
    }
}
