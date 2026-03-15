<?php
/**
 * GT_Router — URL parsing and request dispatch.
 * Matches Go server.go parseRoute() + handleRoute().
 */
class GT_Router {
    private $store;
    private $auth;
    private $blobs;
    private $heads;
    private $inbox;
    private $grants;

    public function __construct($store, $auth) {
        $this->store = $store;
        $this->auth = $auth;
        $this->grants = new GT_Grants($store, $auth);
        $this->blobs = new GT_Blobs($store, $auth, $this->grants);
        $this->heads = new GT_Heads($store, $auth);
        $this->inbox = new GT_Inbox($store, $auth);
    }

    /**
     * Dispatch a /gt/v1/... request.
     * $path is everything after /gt/v1/
     */
    public function dispatch($path) {
        $this->set_cors_headers();

        // Handle OPTIONS preflight
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(204);
            return;
        }

        // Health endpoint
        if ($path === 'health') {
            header('Content-Type: application/json');
            echo json_encode(['status' => 'ok']);
            return;
        }

        // Registration endpoint
        $path = rtrim($path, '/');
        if ($path === 'register') {
            $reg = new GT_Register($this->store);
            $reg->handle();
            return;
        }
        // Registration availability check: register/check/{userID}
        if (preg_match('#^register/check/([a-z0-9]*)$#', $path, $m)) {
            $reg = new GT_Register($this->store);
            $reg->handle_check($m[1]);
            return;
        }
        // Parse route
        $route = $this->parse_route($path);
        if (is_string($route)) {
            self::error_json(400, 'bad_request', $route);
            return;
        }

        $method = $_SERVER['REQUEST_METHOD'];

        switch ($route['resource']) {
            case 'blobs':
                $this->blobs->handle($method, $route);
                break;
            case 'heads':
                $this->heads->handle($method, $route);
                break;
            case 'inbox':
                $this->inbox->handle($method, $route);
                break;
            case 'grants':
                $this->grants->handle($method, $route);
                break;
            default:
                self::error_json(404, 'not_found', 'unknown resource');
        }
    }

    /**
     * Parse /gt/v1/ path into route components.
     * Returns array or error string.
     *
     * Expected paths:
     *   {did}/blobs/sha256/{hex}
     *   {did}/blobs/sha256/{hex}:meta
     *   {did}/heads/{name}
     *   {did}/inbox
     *   {did}/inbox/{id}
     */
    private function parse_route($path) {
        if (empty($path)) {
            return 'empty path';
        }

        // Find resource segment
        foreach (['/blobs/', '/heads/', '/inbox', '/grants'] as $seg) {
            $pos = strpos($path, $seg);
            if ($pos === false) continue;

            $did = substr($path, 0, $pos);
            $rest = substr($path, $pos + strlen($seg));

            $route = ['did' => $did, 'resource' => '', 'hash' => '', 'is_meta' => false, 'name' => '', 'inbox_item_id' => '', 'grant_hash' => ''];

            if ($seg === '/blobs/') {
                $route['resource'] = 'blobs';
                // Expect: sha256/{hex} or sha256/{hex}:meta
                $parts = explode('/', $rest, 2);
                if (count($parts) !== 2 || $parts[0] !== 'sha256') {
                    return 'invalid blob path: expected sha256/{hex}';
                }
                $hash_part = $parts[1];
                if (substr($hash_part, -5) === ':meta') {
                    $route['is_meta'] = true;
                    $hash_part = substr($hash_part, 0, -5);
                }
                if (!preg_match('/^[0-9a-f]{64}$/', $hash_part)) {
                    return 'invalid blob hash: expected 64 hex chars';
                }
                $route['hash'] = $hash_part;

            } elseif ($seg === '/heads/') {
                $route['resource'] = 'heads';
                if (empty($rest)) {
                    return 'missing head name';
                }
                // Validate head name: alphanumeric, hyphens, underscores
                if (!preg_match('/^[a-zA-Z0-9_-]+$/', $rest)) {
                    return 'invalid head name';
                }
                $route['name'] = $rest;

            } elseif ($seg === '/inbox') {
                $route['resource'] = 'inbox';
                $rest = ltrim($rest, '/');
                if (!empty($rest)) {
                    if (!preg_match('/^[0-9a-fTZ-]+$/', $rest) || strpos($rest, '..') !== false) {
                        return 'invalid inbox item ID';
                    }
                    $route['inbox_item_id'] = basename($rest);
                }
            } elseif ($seg === '/grants') {
                $route['resource'] = 'grants';
                $rest = ltrim($rest, '/');
                if (!empty($rest)) {
                    if (!preg_match('/^[0-9a-f]{64}$/', $rest)) {
                        return 'invalid grant hash: expected 64 hex chars';
                    }
                    $route['grant_hash'] = $rest;
                }
            }

            return $route;
        }

        return 'unknown resource type';
    }

    /**
     * Set CORS headers for cross-origin requests.
     */
    private function set_cors_headers() {
        $origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '*';
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Access-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, X-GT-DID, X-GT-Timestamp, X-GT-Signature, X-GT-Grant');
        header('Access-Control-Max-Age: 86400');
        header('Cache-Control: no-store, no-cache');
    }

    /**
     * Send JSON error response.
     */
    public static function error_json($status, $code, $message) {
        http_response_code($status);
        header('Content-Type: application/json');
        echo json_encode(['error' => $code, 'message' => $message]);
    }
}
