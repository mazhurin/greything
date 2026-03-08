<?php
/**
 * GT_DID_Server — Serves DID documents at /.well-known/did.json and subpaths.
 */
class GT_DID_Server {

    /**
     * Serve root DID document: /.well-known/did.json
     */
    public function serve_root() {
        $this->set_headers();
        $hosted_dids = get_option('gt_storage_dids', []);
        foreach ($hosted_dids as $entry) {
            if (isset($entry['path']) && $entry['path'] === '') {
                $data = $this->load_did_file($entry['file']);
                if ($data !== false) {
                    echo $data;
                    return;
                }
            }
        }
        http_response_code(404);
        echo json_encode(['error' => 'not_found', 'message' => 'no root DID document configured']);
    }

    /**
     * Serve sub-path DID document: /{path}/did.json
     */
    public function serve_path($path) {
        $this->set_headers();
        $hosted_dids = get_option('gt_storage_dids', []);
        foreach ($hosted_dids as $entry) {
            if (isset($entry['path']) && $entry['path'] === $path) {
                $data = $this->load_did_file($entry['file']);
                if ($data !== false) {
                    echo $data;
                    return;
                }
            }
        }
        http_response_code(404);
        echo json_encode(['error' => 'not_found', 'message' => 'DID document not found']);
    }

    private function load_did_file($filename) {
        $path = GT_STORAGE_DIR . '/dids/' . basename($filename);
        if (!file_exists($path)) return false;
        return file_get_contents($path);
    }

    private function set_headers() {
        header('Content-Type: application/json');
        header('Cache-Control: no-cache');
        $origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '*';
        header('Access-Control-Allow-Origin: ' . $origin);
    }
}
