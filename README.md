# PHED
PHED is a PHP Encryption and Decryption Library

# Features
* AES-256-CBC Encryption and Decryption: The PHED class uses aes-256-cbc for secure encryption and decryption of strings, which is a robust and widely trusted algorithm.
* HMAC Verification: Ensures the integrity of the encrypted data by calculating and verifying an HMAC (Hash-based Message Authentication Code) using the SHA-512 algorithm.
* Key Derivation with PBKDF2: Keys are derived using the PBKDF2 function (hash_pbkdf2) with 500,000 iterations for added security against brute-force attacks.
* Exception Handling: The class catches exceptions during encryption and decryption processes and returns detailed error messages, encapsulated in an array structure that includes the status (true or false), message, and the resultant data.

# Usage Guide
* Setting a Custom Key:
You can set a custom encryption key using the key method.
```
phed::key("my_custom_key");
```

* Setting a Encryption salt:
You can set a custom encryption salt using the salt method.
```
phed::salt("my_custom_salt");
```

* Encrypting a String:
To encrypt a string, use the make method and pass the string and the action (en, encrypt, or enc).
```
$encrypted = PHED::make("Your sensitive data", "encrypt");
if ($encrypted['status']) {
    echo "Encrypted Data: " . $encrypted['data'];
} else {
    echo "Error: " . $encrypted['message'];
}
```

* Decrypting a String:
To decrypt the previously encrypted string, use the make method with the de or decrypt action.
```
$decrypted = PHED::make($encrypted['data'], "decrypt");
if ($decrypted['status']) {
    echo "Decrypted Data: " . $decrypted['data'];
} else {
    echo "Error: " . $decrypted['message'];
}
```

* Handling Errors:
The class automatically catches and handles any errors that occur during the encryption/decryption process, returning them as part of the response array.
```
$response = PHED::make("Invalid string", "decrypt");
if (!$response['status']) {
    echo "Error: " . $response['message'];
}
```
