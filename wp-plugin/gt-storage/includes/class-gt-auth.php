<?php
/**
 * GT_Auth — Ed25519 signature verification and DID resolution.
 * Matches Go auth.go: Authenticate() and TryAuthenticate().
 */
class GT_Auth {
    private $store;
    private $did_cache = [];

    const MAX_TIMESTAMP_AGE = 300; // 5 minutes

    public function __construct($store) {
        $this->store = $store;
    }

    /**
     * Authenticate a request. Returns ['did' => string, 'body' => string] or error string.
     * Auth headers: X-GT-DID, X-GT-Timestamp, X-GT-Signature
     * Signature payload: "{timestamp}|{method}|{path}|{bodyHash}"
     */
    public function authenticate($method, $path, $raw_body) {
        $did = $this->get_header('X-GT-DID');
        $timestamp = $this->get_header('X-GT-Timestamp');
        $signature = $this->get_header('X-GT-Signature');

        if (empty($did) || empty($timestamp) || empty($signature)) {
            return ['error' => 'missing auth headers'];
        }

        // Verify timestamp freshness
        $ts = strtotime($timestamp);
        if ($ts === false) {
            return ['error' => 'invalid timestamp format'];
        }
        if (abs(time() - $ts) > self::MAX_TIMESTAMP_AGE) {
            return ['error' => 'timestamp too old'];
        }

        // Compute body hash
        $body_hash = 'sha256-' . hash('sha256', $raw_body);

        // Build signature payload
        $payload = $timestamp . '|' . $method . '|' . $path . '|' . $body_hash;

        // Decode signature (base64url)
        $sig_bytes = self::base64url_decode($signature);
        if ($sig_bytes === false) {
            return ['error' => 'invalid signature encoding'];
        }

        // Resolve DID to Ed25519 public keys
        $keys = $this->resolve_ed25519_keys($did);
        if (is_string($keys)) {
            return ['error' => 'resolving DID: ' . $keys];
        }

        // Try each key
        foreach ($keys as $pub_key) {
            if (sodium_crypto_sign_verify_detached($sig_bytes, $payload, $pub_key)) {
                return ['did' => $did, 'body' => $raw_body];
            }
        }

        return ['error' => 'signature verification failed'];
    }

    /**
     * Resolve a DID to its Ed25519 public keys.
     * Returns array of 32-byte public keys, or error string.
     */
    public function resolve_ed25519_keys($did) {
        // Check cache
        if (isset($this->did_cache[$did])) {
            return $this->did_cache[$did];
        }

        $doc = $this->fetch_did_document($did);
        if (is_string($doc)) {
            return $doc; // error
        }

        $keys = [];
        if (!isset($doc['verificationMethod']) || !is_array($doc['verificationMethod'])) {
            return 'no verificationMethod in DID document';
        }

        foreach ($doc['verificationMethod'] as $vm) {
            if (!isset($vm['type']) || $vm['type'] !== 'Ed25519VerificationKey2020') continue;
            if (empty($vm['publicKeyMultibase'])) continue;

            $raw = self::decode_multibase($vm['publicKeyMultibase']);
            if ($raw !== false && strlen($raw) === 32) {
                $keys[] = $raw;
            }
        }

        if (empty($keys)) {
            return 'no Ed25519 keys found in DID document';
        }

        $this->did_cache[$did] = $keys;
        return $keys;
    }

    /**
     * Resolve DID document for a given DID.
     * Checks local storage first, then fetches via HTTP.
     */
    private function fetch_did_document($did) {
        // Try local first
        $local = $this->try_local_did($did);
        if ($local !== false) {
            return $local;
        }

        // Fetch via HTTP (did:web resolution)
        $url = self::did_web_to_url($did);
        if ($url === false) {
            return 'unsupported DID method';
        }

        $response = wp_remote_get($url, ['timeout' => 10, 'sslverify' => true]);
        if (is_wp_error($response)) {
            return 'failed to fetch DID document: ' . $response->get_error_message();
        }
        if (wp_remote_retrieve_response_code($response) !== 200) {
            return 'DID document fetch returned ' . wp_remote_retrieve_response_code($response);
        }

        $body = wp_remote_retrieve_body($response);
        $doc = json_decode($body, true);
        if (!is_array($doc)) {
            return 'invalid DID document JSON';
        }

        return $doc;
    }

    /**
     * Try to load DID document from local storage.
     */
    private function try_local_did($did) {
        $hosted_dids = get_option('gt_storage_dids', []);
        foreach ($hosted_dids as $entry) {
            if (isset($entry['did']) && $entry['did'] === $did && isset($entry['file'])) {
                $data = $this->store->get('dids/' . $entry['file']);
                if ($data !== false) {
                    $doc = json_decode($data, true);
                    if (is_array($doc)) return $doc;
                }
            }
        }
        return false;
    }

    /**
     * Convert did:web DID to HTTP URL.
     * did:web:example.com → https://example.com/.well-known/did.json
     * did:web:example.com:family:bob → https://example.com/family/bob/did.json
     */
    public static function did_web_to_url($did) {
        if (strpos($did, 'did:web:') !== 0) {
            return false;
        }
        $parts = explode(':', substr($did, 8)); // strip "did:web:"
        if (empty($parts)) return false;

        $domain = urldecode($parts[0]);
        if (count($parts) === 1) {
            return 'https://' . $domain . '/.well-known/did.json';
        }

        $path = implode('/', array_slice($parts, 1));
        return 'https://' . $domain . '/' . $path . '/did.json';
    }

    /**
     * Decode multibase-encoded value (z = base58btc).
     */
    public static function decode_multibase($value) {
        if (empty($value) || $value[0] !== 'z') {
            return false;
        }
        return self::base58_decode(substr($value, 1));
    }

    /**
     * Base58 decode (Bitcoin alphabet).
     */
    public static function base58_decode($str) {
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        $base = strlen($alphabet);

        $num = gmp_init(0);
        for ($i = 0; $i < strlen($str); $i++) {
            $pos = strpos($alphabet, $str[$i]);
            if ($pos === false) return false;
            $num = gmp_add(gmp_mul($num, $base), $pos);
        }

        $hex = gmp_strval($num, 16);
        if (strlen($hex) % 2 !== 0) $hex = '0' . $hex;

        // Count leading '1's (zero bytes)
        $leading = 0;
        for ($i = 0; $i < strlen($str) && $str[$i] === '1'; $i++) {
            $leading++;
        }

        return str_repeat("\0", $leading) . hex2bin($hex);
    }

    /**
     * Base64url decode.
     */
    public static function base64url_decode($str) {
        $str = strtr($str, '-_', '+/');
        $pad = strlen($str) % 4;
        if ($pad) $str .= str_repeat('=', 4 - $pad);
        return base64_decode($str, true);
    }

    /**
     * Get HTTP request header (handles Apache/nginx differences).
     */
    private function get_header($name) {
        // Convert X-GT-DID to HTTP_X_GT_DID
        $server_key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
        if (isset($_SERVER[$server_key])) {
            return $_SERVER[$server_key];
        }
        // Also try getallheaders() for Apache
        if (function_exists('getallheaders')) {
            $headers = getallheaders();
            if (isset($headers[$name])) return $headers[$name];
            // Case-insensitive search
            foreach ($headers as $k => $v) {
                if (strcasecmp($k, $name) === 0) return $v;
            }
        }
        return '';
    }
}
