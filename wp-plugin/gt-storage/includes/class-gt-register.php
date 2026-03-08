<?php
/**
 * GT_Register — Registration API endpoint.
 * Accepts a DID document + user ID, stores it, and auto-configures the DID.
 */
class GT_Register {
    private $store;

    public function __construct($store) {
        $this->store = $store;
    }

    /**
     * Handle POST /gt/v1/register
     * Body: { "userID": "alice", "didDocument": {...} }
     *
     * No auth required (the user is creating their identity).
     * The DID document contains the public keys that will be used for future auth.
     */
    public function handle() {
        // CORS
        $origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '*';
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Access-Control-Allow-Methods: POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type');

        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(204);
            return;
        }

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $this->error_json(405, 'method_not_allowed', 'use POST');
            return;
        }

        // Check if registration is enabled
        $reg_enabled = get_option('gt_storage_registration', 'open');
        if ($reg_enabled === 'closed') {
            $this->error_json(403, 'registration_closed', 'registration is currently closed');
            return;
        }

        $body = file_get_contents('php://input');
        $req = json_decode($body, true);
        if (!is_array($req)) {
            $this->error_json(400, 'bad_request', 'invalid JSON body');
            return;
        }

        $user_id = isset($req['userID']) ? $req['userID'] : '';
        $did_doc = isset($req['didDocument']) ? $req['didDocument'] : null;

        if (!is_array($did_doc)) {
            $this->error_json(400, 'bad_request', 'didDocument is required');
            return;
        }

        // Determine DID and path
        $domain = $_SERVER['HTTP_HOST'];

        if (empty($user_id)) {
            // Root DID: did:web:example.com
            $did = 'did:web:' . $domain;
            $did_path = ''; // serves at /.well-known/did.json
            $filename = 'root.json';
        } else {
            // Validate user ID
            if (!preg_match('/^[a-z0-9]{3,20}$/', $user_id)) {
                $this->error_json(400, 'bad_request', 'invalid userID: use 3-20 lowercase alphanumeric characters');
                return;
            }
            // Sub-path DID: did:web:example.com:users:alice
            $did = 'did:web:' . $domain . ':users:' . $user_id;
            $did_path = 'users/' . $user_id;
            $filename = 'users-' . $user_id . '.json';
        }

        // Check if DID already exists
        $hosted_dids = get_option('gt_storage_dids', []);
        foreach ($hosted_dids as $entry) {
            if (isset($entry['did']) && $entry['did'] === $did) {
                $this->error_json(409, 'already_exists', 'this DID is already registered');
                return;
            }
        }

        // Verify the DID document has the expected DID ID
        if (!isset($did_doc['id']) || $did_doc['id'] !== $did) {
            $this->error_json(400, 'bad_request', 'didDocument.id must match ' . $did);
            return;
        }

        // Verify the DID document has at least one Ed25519 verification method
        $has_ed25519 = false;
        if (isset($did_doc['verificationMethod']) && is_array($did_doc['verificationMethod'])) {
            foreach ($did_doc['verificationMethod'] as $vm) {
                if (isset($vm['type']) && $vm['type'] === 'Ed25519VerificationKey2020') {
                    $has_ed25519 = true;
                    break;
                }
            }
        }
        if (!$has_ed25519) {
            $this->error_json(400, 'bad_request', 'didDocument must contain at least one Ed25519VerificationKey2020');
            return;
        }

        // Store DID document
        $did_json = json_encode($did_doc, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (!$this->store->put('dids/' . $filename, $did_json)) {
            $this->error_json(500, 'internal', 'failed to store DID document');
            return;
        }

        // Create storage directories
        wp_mkdir_p(GT_STORAGE_DIR . '/' . $did . '/blobs/sha256');
        wp_mkdir_p(GT_STORAGE_DIR . '/' . $did . '/heads');
        wp_mkdir_p(GT_STORAGE_DIR . '/' . $did . '/inbox');

        // Add to hosted DIDs
        $hosted_dids[] = [
            'did' => $did,
            'path' => $did_path,
            'file' => $filename,
            'registered_at' => gmdate('Y-m-d\TH:i:s\Z'),
        ];
        update_option('gt_storage_dids', $hosted_dids);

        // Return success
        http_response_code(201);
        header('Content-Type: application/json');
        echo json_encode([
            'did' => $did,
            'storageEndpoint' => 'https://' . $domain . '/gt/v1/' . $did,
            'didDocumentURL' => empty($did_path)
                ? 'https://' . $domain . '/.well-known/did.json'
                : 'https://' . $domain . '/' . $did_path . '/did.json',
        ]);
    }

    /**
     * Handle GET /gt/v1/register/check/{userID}
     * Returns 200 if taken, 404 if available.
     */
    public function handle_check($user_id) {
        header('Access-Control-Allow-Origin: *');
        header('Content-Type: application/json');

        if (empty($user_id)) {
            // Check root DID
            $did = 'did:web:' . $_SERVER['HTTP_HOST'];
        } else {
            $did = 'did:web:' . $_SERVER['HTTP_HOST'] . ':users:' . $user_id;
        }

        $hosted_dids = get_option('gt_storage_dids', []);
        foreach ($hosted_dids as $entry) {
            if (isset($entry['did']) && $entry['did'] === $did) {
                echo json_encode(['available' => false, 'did' => $did]);
                return;
            }
        }

        http_response_code(404);
        echo json_encode(['available' => true, 'did' => $did]);
    }


    private function error_json($status, $code, $message) {
        http_response_code($status);
        header('Content-Type: application/json');
        echo json_encode(['error' => $code, 'message' => $message]);
    }
}
