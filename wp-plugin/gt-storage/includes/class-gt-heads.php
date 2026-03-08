<?php
/**
 * GT_Heads — Head handlers with CAS (Compare-And-Swap) semantics.
 * Matches Go heads.go.
 */
class GT_Heads {
    private $store;
    private $auth;

    public function __construct($store, $auth) {
        $this->store = $store;
        $this->auth = $auth;
    }

    public function handle($method, $route) {
        switch ($method) {
            case 'GET': $this->handle_get($route); break;
            case 'PUT': $this->handle_put($route); break;
            default:    GT_Router::error_json(405, 'method_not_allowed', 'use GET or PUT'); break;
        }
    }

    private function head_key($did, $name) {
        return $did . '/heads/' . $name;
    }

    // --- GET head ---

    private function handle_get($route) {
        $key = $this->head_key($route['did'], $route['name']);
        $data = $this->store->get($key);
        if ($data === false) {
            GT_Router::error_json(404, 'not_found', 'head not found');
            return;
        }

        $head = json_decode($data, true);
        if (!is_array($head)) {
            GT_Router::error_json(500, 'internal', 'corrupt head data');
            return;
        }

        header('Content-Type: application/json');
        echo json_encode($head);
    }

    // --- PUT head (CAS) ---

    private function handle_put($route) {
        $raw_body = file_get_contents('php://input');
        $auth_result = $this->auth->authenticate('PUT', '/gt/v1/' . $route['did'] . '/heads/' . $route['name'], $raw_body);
        if (isset($auth_result['error'])) {
            GT_Router::error_json(401, 'unauthorized', $auth_result['error']);
            return;
        }

        if ($auth_result['did'] !== $route['did']) {
            GT_Router::error_json(403, 'forbidden', 'not the owner of this namespace');
            return;
        }

        $req = json_decode($raw_body, true);
        if (!is_array($req) || !isset($req['head'])) {
            GT_Router::error_json(400, 'bad_request', 'invalid JSON body');
            return;
        }
        if (empty($req['head'])) {
            GT_Router::error_json(400, 'bad_request', 'head value is required');
            return;
        }

        $expected = isset($req['expected']) ? $req['expected'] : '';
        $key = $this->head_key($route['did'], $route['name']);

        // CAS: read current, compare, write
        // Use file locking for atomicity
        $current_data = $this->store->get($key);

        if ($current_data === false) {
            // Head doesn't exist — expected must be empty
            if ($expected !== '') {
                GT_Router::error_json(409, 'conflict', 'CAS conflict: expected value does not match current');
                return;
            }
        } else {
            $current = json_decode($current_data, true);
            if (!is_array($current)) {
                GT_Router::error_json(500, 'internal', 'corrupt head data');
                return;
            }
            if ($current['head'] !== $expected) {
                GT_Router::error_json(409, 'conflict', 'CAS conflict: expected value does not match current');
                return;
            }
        }

        $new_head = [
            'head' => $req['head'],
            'updatedAt' => gmdate('Y-m-d\TH:i:s\Z'),
        ];

        // Delete old then put new (since Put may not overwrite)
        $this->store->delete($key);
        if (!$this->store->put($key, json_encode($new_head))) {
            GT_Router::error_json(500, 'internal', 'failed to store head');
            return;
        }

        header('Content-Type: application/json');
        echo json_encode($new_head);
    }
}
