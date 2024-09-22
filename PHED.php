<?php

/**
 * PHED is a PHP Encryption and Decryption Library
 * Author: Sakibur Rahman @sakibweb
 * A PHP library for securely encrypting and decrypting strings using AES-256-CBC and HMAC verification.
 */
class PHED {

    /**
     * Default encryption key.
     * @var string
     */
    private static $key = "default_key";

    /**
     * Encrypts the provided plaintext with a derived key and salt.
     * @param string $plaintext
     * @param string $key
     * @return string
     */
    private function encrypt_string($plaintext, $key) {
        try {
            $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
            $ciphertext = openssl_encrypt($plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
            $hmac = hash_hmac('sha512', $iv . $ciphertext, $key, true);
            return base64_encode($iv . $hmac . $ciphertext);
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Decrypts the provided ciphertext with a derived key and salt.
     * @param string $ciphertext
     * @param string $key
     * @return array
     */
    private function decrypt_string($ciphertext, $key) {
        try {
            $ciphertext = base64_decode($ciphertext);
            $iv_length = openssl_cipher_iv_length('aes-256-cbc');
            $iv = substr($ciphertext, 0, $iv_length);
            $hmac = substr($ciphertext, $iv_length, 64);
            $ciphertext = substr($ciphertext, $iv_length + 64);

            $calculated_hmac = hash_hmac('sha512', $iv . $ciphertext, $key, true);

            if (!hash_equals($hmac, $calculated_hmac)) {
                return ['status' => false, 'message' => "HMAC verification failed.", 'data' => null];
            }

            $decrypted = openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
            return ['status' => true, 'message' => 'Decryption successful.', 'data' => $decrypted];
        } catch (Exception $e) {
            return ['status' => false, 'message' => 'Decryption failed.', 'data' => null];
        }
    }

    /**
     * Derives a secure encryption key from a given key and salt using PBKDF2.
     * @param string $key
     * @param string $salt
     * @return string
     */
    private function derive_key($key, $salt) {
        try {
            return hash_pbkdf2('sha512', $key, $salt, 100000, 32, true);
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Encrypts or decrypts the string based on the provided action.
     * @param string $string
     * @param string $key
     * @param string $action
     * @return array
     */
    public function hide($string, $key, $action) {
        try {
            if ($action === 'encrypt') {
                $salt = openssl_random_pseudo_bytes(16);
                $derived_key = $this->derive_key($key, $salt);
                if ($derived_key === false) {
                    return ['status' => false, 'message' => 'Failed to derive encryption key.', 'data' => null];
                }
                $encrypted_string = $this->encrypt_string($string, $derived_key);
                if ($encrypted_string === false) {
                    return ['status' => false, 'message' => 'Encryption failed.', 'data' => null];
                }
                return [
                    'status' => true,
                    'message' => 'Encryption successful.',
                    'data' => base64_encode($salt . $encrypted_string)
                ];
            } elseif ($action === 'decrypt') {
                $ciphertext = base64_decode($string);
                $salt = substr($ciphertext, 0, 16); 
                $encrypted_data = substr($ciphertext, 16);
                $derived_key = $this->derive_key($key, $salt);
                if ($derived_key === false) {
                    return ['status' => false, 'message' => 'Failed to derive decryption key.', 'data' => null];
                }
                return $this->decrypt_string($encrypted_data, $derived_key);
            } else {
                return ['status' => false, 'message' => 'Invalid action specified.', 'data' => null];
            }
        } catch (Exception $e) {
            return ['status' => false, 'message' => 'An error occurred.', 'data' => null];
        }
    }

    public static function make($string, $action) {
        $key = self::$key;
        $phed = new self();
        return $phed->hide($string, $key, $action);
    }

    public static function key($new_key) {
        self::$key = $new_key;
    }
}
?>
