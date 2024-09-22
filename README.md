# PHED: PHP Encryption and Decryption Library

PHED is a PHP Encryption and Decryption Library designed for securely encrypting and decrypting strings using AES-256-CBC and HMAC verification.

## Features
- **AES-256-CBC Encryption and Decryption**: Utilizes the `aes-256-cbc` algorithm for secure encryption and decryption, a robust and widely trusted method in the industry.
- **HMAC Verification**: Ensures the integrity of the encrypted data by calculating and verifying an HMAC (Hash-based Message Authentication Code) using the SHA-512 algorithm.
- **Key Derivation with PBKDF2**: Keys are derived using the PBKDF2 function (`hash_pbkdf2`) with 100,000 iterations for added security against brute-force attacks, making it more resistant to attacks.
- **Exception Handling**: Catches exceptions during encryption and decryption processes and returns detailed error messages in a structured array format, including status, message, and data.

## Security Considerations
- **Encryption Key**: Always ensure that your encryption key is complex and kept secret. The default key should be changed to a secure key of at least 18 characters.
- **Salt Management**: The library generates secure salts for each encryption to ensure unique derived keys, further enhancing security.

## Usage Guide

### Setting a Custom Key
To set a custom encryption key, use the `key` method. This key should be at least 18 characters long.
```
$result = PHED::key("new_secure_key");
if ($result['status']) {
    echo "Key updated successfully.";
} else {
    echo "Error: " . $result['message'];
}
```

### Encrypting a String:
To encrypt a string, use the make method and pass the string and the action (en, encrypt, or enc).
```
$encrypted = PHED::make("Your sensitive data", "encrypt");
if ($encrypted['status']) {
    echo "Encrypted Data: " . $encrypted['data'];
} else {
    echo "Error: " . $encrypted['message'];
}
```
Response Structure:
* **status**: Indicates success or failure (true/false).
* **message**: Descriptive message regarding the operation.
* **data**: Contains the encrypted data or null on failure.

### Decrypting a String:
To decrypt the previously encrypted string, use the make method with the de or decrypt action.
```
$decrypted = PHED::make($encrypted['data'], "decrypt");
if ($decrypted['status']) {
    echo "Decrypted Data: " . $decrypted['data'];
} else {
    echo "Error: " . $decrypted['message'];
}
```
**Important**: Ensure that the input to the decrypt action is the result from the encrypt action.

### Handling Errors:
The library automatically handles errors that may occur during encryption or decryption. You can check the status and handle messages accordingly.
```
$response = PHED::make("Invalid string", "decrypt");
if (!$response['status']) {
    echo "Error: " . $response['message'];
}
```

### Security Score Evaluation:
The library includes a score method to evaluate the security of the current setup based on key length, algorithm security, and the availability of integrity measures.
```
$score = PHED::score();
if ($score < 100) {
    echo "Warning: Security score too low: {$score}/100.";
}
```

# Security Considerations
* Ensure that your encryption key is stored securely and not hard-coded in your application.
* Regularly update your keys and monitor for unauthorized access to sensitive data.
* Evaluate your implementation periodically to maintain compliance with security standards.

# Conclusion
The PHED library provides a secure and efficient way to handle encryption and decryption in PHP applications. Always adhere to best practices for key management and data integrity to ensure the highest level of security.
