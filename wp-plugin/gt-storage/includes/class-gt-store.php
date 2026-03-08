<?php
/**
 * GT_Store — Filesystem storage adapter.
 * Matches Go StorageAdapter interface: Get, Put, Delete, Exists, List.
 */
class GT_Store {
    private $base_dir;

    public function __construct($base_dir) {
        $this->base_dir = rtrim($base_dir, '/');
    }

    /**
     * Resolve key to filesystem path with traversal prevention.
     */
    private function key_path($key) {
        $key = str_replace('\\', '/', $key);
        // Prevent directory traversal
        if (strpos($key, '..') !== false) {
            return false;
        }
        $path = $this->base_dir . '/' . $key;
        $real = realpath(dirname($path));
        if ($real === false) {
            // Parent dir doesn't exist yet — that's OK for put
            // But verify it would be under base_dir
            $parts = explode('/', $key);
            foreach ($parts as $part) {
                if ($part === '' || $part === '.' || $part === '..') {
                    return false;
                }
            }
            return $path;
        }
        if (strpos($real, realpath($this->base_dir)) !== 0) {
            return false;
        }
        return $path;
    }

    /**
     * Get retrieves data by key. Returns false if not found.
     */
    public function get($key) {
        $path = $this->key_path($key);
        if ($path === false || !file_exists($path) || !is_file($path)) {
            return false;
        }
        return file_get_contents($path);
    }

    /**
     * Put stores data at key. Atomic write via temp+rename.
     */
    public function put($key, $data) {
        $path = $this->key_path($key);
        if ($path === false) {
            return false;
        }
        $dir = dirname($path);
        if (!is_dir($dir)) {
            if (!wp_mkdir_p($dir)) {
                return false;
            }
        }
        $tmp = $path . '.tmp.' . uniqid();
        if (file_put_contents($tmp, $data) === false) {
            return false;
        }
        if (!rename($tmp, $path)) {
            @unlink($tmp);
            return false;
        }
        return true;
    }

    /**
     * Delete removes data at key. Returns false if not found.
     */
    public function delete($key) {
        $path = $this->key_path($key);
        if ($path === false || !file_exists($path)) {
            return false;
        }
        return unlink($path);
    }

    /**
     * Exists checks if key exists.
     */
    public function exists($key) {
        $path = $this->key_path($key);
        if ($path === false) {
            return false;
        }
        return file_exists($path) && is_file($path);
    }

    /**
     * List returns all keys under a prefix.
     */
    public function list_keys($prefix) {
        $dir = $this->key_path($prefix);
        if ($dir === false) {
            return [];
        }
        // If prefix points to a directory, scan it
        if (!is_dir($dir)) {
            // prefix might be a partial path — scan parent
            $parent = dirname($dir);
            $base = basename($dir);
            if (!is_dir($parent)) {
                return [];
            }
            $keys = [];
            $this->scan_dir($parent, $prefix, $keys, $base);
            return $keys;
        }
        $keys = [];
        $this->scan_dir($dir, $prefix, $keys);
        return $keys;
    }

    private function scan_dir($dir, $prefix, &$keys, $name_prefix = '') {
        $items = @scandir($dir);
        if ($items === false) return;
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            if ($name_prefix !== '' && strpos($item, $name_prefix) !== 0) continue;
            $full = $dir . '/' . $item;
            $rel_key = $prefix . ($name_prefix === '' ? $item : $item);
            if (is_dir($full)) {
                $this->scan_dir($full, $prefix . $item . '/', $keys);
            } else {
                // Skip temp files
                if (strpos($item, '.tmp.') !== false) continue;
                $keys[] = $rel_key;
            }
        }
    }

    /**
     * Count keys under a prefix (for inbox limit checking).
     */
    public function count_keys($prefix) {
        return count($this->list_keys($prefix));
    }
}
