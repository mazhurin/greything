<?php
/**
 * GT_Grants — Capability grant handlers.
 * Matches Go server.go grant handlers.
 */
class GT_Grants {
    private $store;
    private $auth;

    public function __construct($store, $auth) {
        $this->store = $store;
        $this->auth = $auth;
    }

    public function handle($method, $route) {
        if (empty($route['grant_hash'])) {
            // /gt/v1/{did}/grants
            if ($method === 'POST') {
                $this->handle_post($route);
            } else {
                GT_Router::error_json(405, 'method_not_allowed', 'use POST');
            }
        } else {
            // /gt/v1/{did}/grants/{hash}
            if ($method === 'GET') {
                $this->handle_get($route);
            } else {
                GT_Router::error_json(405, 'method_not_allowed', 'use GET');
            }
        }
    }

    /**
     * POST /gt/v1/{did}/grants — store a signed grant.
     */
    private function handle_post($route) {
        $raw_body = file_get_contents('php://input');
        $auth_result = $this->auth->authenticate('POST', '/gt/v1/' . $route['did'] . '/grants', $raw_body);
        if (isset($auth_result['error'])) {
            GT_Router::error_json(401, 'unauthorized', $auth_result['error']);
            return;
        }

        $grant = json_decode($raw_body, true);
        if (!is_array($grant)) {
            GT_Router::error_json(400, 'bad_request', 'invalid JSON');
            return;
        }

        // Grant issuer must match namespace
        if (!isset($grant['issuer']) || $grant['issuer'] !== $route['did']) {
            GT_Router::error_json(403, 'forbidden', 'grant issuer must match namespace');
            return;
        }

        // Verify grant signature
        if (!$this->verify_grant_signature($grant)) {
            GT_Router::error_json(400, 'bad_request', 'grant signature verification failed');
            return;
        }

        // Compute grant hash from canonical JSON
        $grant_hash = $this->compute_grant_hash($grant);
        if ($grant_hash === false) {
            GT_Router::error_json(500, 'internal', 'failed to compute grant hash');
            return;
        }

        // Store grant
        $key = $this->grant_key($route['did'], $grant_hash);
        $this->store->put($key, $raw_body);

        http_response_code(201);
        header('Content-Type: application/json');
        echo json_encode(['grantHash' => $grant_hash]);
    }

    /**
     * GET /gt/v1/{did}/grants/{hash} — retrieve a grant.
     */
    private function handle_get($route) {
        $key = $this->grant_key($route['did'], 'sha256-' . $route['grant_hash']);
        $data = $this->store->get($key);
        if ($data === false) {
            GT_Router::error_json(404, 'not_found', 'grant not found');
            return;
        }

        header('Content-Type: application/json');
        echo $data;
    }

    /**
     * Verify Ed25519 signature on a grant.
     */
    private function verify_grant_signature($grant) {
        if (!isset($grant['sig']) || !is_array($grant['sig'])) return false;
        if (!isset($grant['sig']['alg']) || $grant['sig']['alg'] !== 'Ed25519') return false;
        if (empty($grant['sig']['value'])) return false;
        if (empty($grant['issuer'])) return false;

        // Build canonical JSON without sig field
        $grant_copy = $grant;
        unset($grant_copy['sig']);
        $canonical = self::canonical_json($grant_copy);
        if ($canonical === false) return false;

        // Decode signature
        $sig_bytes = GT_Auth::base64url_decode($grant['sig']['value']);
        if ($sig_bytes === false || strlen($sig_bytes) !== 64) return false;

        // Resolve issuer's Ed25519 keys
        $keys = $this->auth->resolve_ed25519_keys($grant['issuer']);
        if (is_string($keys)) return false; // error string

        foreach ($keys as $pub_key) {
            if (sodium_crypto_sign_verify_detached($sig_bytes, $canonical, $pub_key)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Compute sha256 hash of canonical JSON of the full grant (including sig).
     */
    private function compute_grant_hash($grant) {
        $canonical = self::canonical_json($grant);
        if ($canonical === false) return false;
        return 'sha256-' . hash('sha256', $canonical);
    }

    /**
     * Validate a grant for blob read access.
     * Returns true if the grant authorizes the reader to read the blob.
     */
    public function validate_grant_for_blob_read($grant, $reader_did, $blob_owner_did, $blob_hash) {
        if (!isset($grant['issuer']) || $grant['issuer'] !== $blob_owner_did) return false;
        if (!isset($grant['subject']) || $grant['subject'] !== $reader_did) return false;
        if (!isset($grant['resource']['kind']) || $grant['resource']['kind'] !== 'blob') return false;
        if (!isset($grant['resource']['hash']) || $grant['resource']['hash'] !== $blob_hash) return false;
        if (!isset($grant['perm']) || !in_array('read', $grant['perm'])) return false;

        $now = time();
        if (!empty($grant['notBefore'])) {
            $nb = strtotime($grant['notBefore']);
            if ($nb !== false && $now < $nb) return false;
        }
        if (!empty($grant['expiresAt'])) {
            $exp = strtotime($grant['expiresAt']);
            if ($exp !== false && $now > $exp) return false;
        }

        return true;
    }

    /**
     * Check grant-based access for a blob GET request.
     * Returns true if access should be allowed.
     */
    public function check_grant_access($route, $caller_did) {
        $grant_hash = isset($_SERVER['HTTP_X_GT_GRANT']) ? $_SERVER['HTTP_X_GT_GRANT'] : '';
        if (empty($grant_hash)) return false;

        // Load grant
        $key = $this->grant_key($route['did'], $grant_hash);
        $data = $this->store->get($key);
        if ($data === false) return false;

        $grant = json_decode($data, true);
        if (!is_array($grant)) return false;

        // Verify grant signature
        if (!$this->verify_grant_signature($grant)) return false;

        // Validate for this blob
        $blob_hash = 'sha256-' . $route['hash'];
        return $this->validate_grant_for_blob_read($grant, $caller_did, $route['did'], $blob_hash);
    }

    // --- Helpers ---

    private function grant_key($did, $grant_hash) {
        $hash = $grant_hash;
        if (strpos($hash, 'sha256-') === 0) {
            $hash = substr($hash, 7);
        }
        return $did . '/grants/' . $hash;
    }

    /**
     * Produce canonical JSON (sorted keys, no whitespace).
     */
    public static function canonical_json($val) {
        if (is_null($val)) return 'null';
        if (is_bool($val)) return $val ? 'true' : 'false';
        if (is_int($val) || is_float($val)) return json_encode($val);
        if (is_string($val)) return json_encode($val, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (is_array($val)) {
            // Check if sequential array
            if (array_values($val) === $val) {
                $items = [];
                foreach ($val as $v) {
                    $items[] = self::canonical_json($v);
                }
                return '[' . implode(',', $items) . ']';
            }
            // Associative array (object) — sort keys
            ksort($val);
            $items = [];
            foreach ($val as $k => $v) {
                $items[] = json_encode((string)$k, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . ':' . self::canonical_json($v);
            }
            return '{' . implode(',', $items) . '}';
        }
        return 'null';
    }
}
