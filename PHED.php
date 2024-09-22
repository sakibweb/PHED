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
     * Default encryption salt.
     * @var string
     */
    private static $salt = "default_salt";

    /**
     * Encrypts the provided plaintext.
     *
     * @param string $plaintext The string to encrypt.
     * @param string $key The encryption key.
     * @param string $iv The initialization vector (IV).
     * @return string The base64 encoded encrypted string.
     */
    private function encrypt_string($plaintext, $key, $iv) {
        try {
            $ciphertext = openssl_encrypt($plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
            $hmac = hash_hmac('sha512', $iv . $ciphertext, $key, true);
            return base64_encode($iv . $hmac . $ciphertext);
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Decrypts the provided ciphertext.
     *
     * @param string $ciphertext The encrypted string.
     * @param string $key The encryption key.
     * @return array The decrypted plaintext or an error message.
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
                return [
                    'status' => false,
                    'message' => "HMAC verification failed.",
                    'data' => null
                ];
            }

            $decrypted = openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
            return [
                'status' => true,
                'message' => 'Decryption successful.',
                'data' => $decrypted
            ];
        } catch (Exception $e) {
            return [
                'status' => false,
                'message' => $e->getMessage(),
                'data' => null
            ];
        }
    }

    /**
     * Derives an encryption key using PBKDF2.
     *
     * @param string $key The raw key.
     * @param string $salt The salt to use for key derivation.
     * @return string The derived key.
     */
    private function derive_key($key, $salt) {
        try {
            return hash_pbkdf2('sha512', $key, $salt, 500000, 32, true);
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Encrypts or decrypts a string based on the specified action.
     *
     * @param string $string The input string.
     * @param string $key The encryption key.
     * @param string $action The action to perform ('en' for encryption, 'de' for decryption).
     * @return array The result as an array with status, message, and data.
     */
    public function hide($string, $key, $action) {
        try {
            $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
            $salt = openssl_random_pseudo_bytes(16);
            $derived_key = $this->derive_key($key, $salt);

            if ($derived_key === false) {
                return [
                    'status' => false,
                    'message' => 'Failed to derive encryption key.',
                    'data' => null
                ];
            }

            if (in_array($action, ["en", "encrypt", "enc"])) {
                $encrypted_string = $this->encrypt_string($string, $derived_key, $iv);
                if ($encrypted_string === false) {
                    return [
                        'status' => false,
                        'message' => 'Encryption failed.',
                        'data' => null
                    ];
                }
                return [
                    'status' => true,
                    'message' => 'Encryption successful.',
                    'data' => base64_encode($salt . $encrypted_string)
                ];
            } elseif (in_array($action, ["de", "decrypt", "dec"])) {
                $ciphertext = base64_decode($string);
                $salt = substr($ciphertext, 0, 16);
                $encrypted_data = substr($ciphertext, 16);
                $derived_key = $this->derive_key($key, $salt);

                if ($derived_key === false) {
                    return [
                        'status' => false,
                        'message' => 'Failed to derive decryption key.',
                        'data' => null
                    ];
                }

                return $this->decrypt_string($encrypted_data, $derived_key);
            } else {
                return [
                    'status' => false,
                    'message' => 'Invalid action specified.',
                    'data' => null
                ];
            }
        } catch (Exception $e) {
            return [
                'status' => false,
                'message' => $e->getMessage(),
                'data' => null
            ];
        }
    }

    /**
     * Public interface to encrypt or decrypt a string using the default key.
     *
     * @param string $string The string to encrypt or decrypt.
     * @param string $action The action to perform ('en', 'de').
     * @return array The result with status, message, and data.
     */
    public static function make($string, $action) {
        $key = self::$key;
        $phed = new self();
        return $phed->hide($string, $key, $action);
    }

    /**
     * Updates the default encryption key.
     *
     * @param string $new_key The new encryption key.
     */
    public static function key($new_key) {
        self::$key = $new_key;
    }

    /**
     * Updates the default encryption salt.
     *
     * @param string $new_salt The new encryption salt.
     */
    public static function salt($new_salt) {
        self::$salt = $new_salt;
    }
}
?>
