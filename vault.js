// src/vault.js

/**
 * @module vault
 * This module provides a secure, in-memory encrypted store. It uses modern
 * cryptographic primitives from Node.js's built-in `crypto` module to ensure
 * confidentiality and integrity of stored data.
 *
 * --- Cryptography Choices ---
 * - Key Derivation: scrypt is used over PBKDF2 as it is more resilient to
 * custom hardware (ASIC/FPGA) attacks, making it a stronger choice for
 * deriving keys from user-supplied passwords.
 * - Encryption: AES-256-GCM (Galois/Counter Mode) is used. This is an
 * Authenticated Encryption with Associated Data (AEAD) cipher. It provides
 * both confidentiality (encryption) and integrity/authenticity through an
 * authentication tag, preventing tampering.
 * - IV (Initialization Vector): A new, cryptographically random 12-byte IV is
 * generated for every single encryption operation to ensure security.
 */

import {
    scrypt,
    createCipheriv,
    createDecipheriv,
    randomBytes,
} from 'crypto';
import { promisify } from 'util';

const scryptAsync = promisify(scrypt);

// --- Constants ---
const KEY_LENGTH = 32; // 32 bytes for AES-256
const SALT_LENGTH = 16; // 16 bytes is a standard salt size
const IV_LENGTH = 12; // 12 bytes is standard for GCM
const AUTH_TAG_LENGTH = 16; // 16 bytes is standard for GCM

// scrypt parameters - these should be tuned based on the target environment's performance.
const SCRYPT_PARAMS = {
    N: 32768, // CPU/memory cost factor (power of 2)
    r: 8, // Block size
    p: 1, // Parallelization factor
};

/**
 * A secure, encrypted in-memory vault.
 */
class Vault {
    #derivedKey = null;
    #salt = null;
    #store = new Map();
    #initialized = false;

    /**
     * Initializes the vault by deriving a key from a master password.
     * This must be called before any other operations can be performed.
     * @param {string} masterPassword - The user's master password.
     */
    async init(masterPassword) {
        if (this.#initialized) {
            throw new Error('Vault has already been initialized.');
        }
        if (typeof masterPassword !== 'string' || masterPassword.length < 12) {
            throw new Error('Master password must be a string of at least 12 characters.');
        }

        this.#salt = randomBytes(SALT_LENGTH);
        this.#derivedKey = await scryptAsync(masterPassword, this.#salt, KEY_LENGTH, SCRYPT_PARAMS);
        this.#initialized = true;
    }

    /**
     * Encrypts and stores a key-value pair in the vault.
     * @param {string} key - The key to associate with the value.
     * @param {string} value - The plaintext value to store.
     * @returns {{success: boolean, error?: string}}
     */
    store(key, value) {
        if (!this.#initialized) {
            return { success: false, error: 'Vault not initialized.' };
        }

        try {
            const iv = randomBytes(IV_LENGTH);
            const cipher = createCipheriv('aes-256-gcm', this.#derivedKey, iv);

            const encryptedValue = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
            const authTag = cipher.getAuthTag();

            // Store the salt, IV, auth tag, and encrypted value together for decryption.
            // A common format is salt:iv:authTag:encryptedValue, all hex-encoded.
            const storedPayload = Buffer.concat([this.#salt, iv, authTag, encryptedValue]).toString('hex');

            this.#store.set(key, storedPayload);
            return { success: true };
        } catch (error) {
            console.error('Encryption failed:', error);
            return { success: false, error: 'Failed to encrypt and store value.' };
        }
    }

    /**
     * Retrieves and decrypts a value from the vault.
     * @param {string} key - The key of the value to retrieve.
     * @returns {{success: boolean, data?: string, error?: string}}
     */
    retrieve(key) {
        if (!this.#initialized) {
            return { success: false, error: 'Vault not initialized.' };
        }
        if (!this.#store.has(key)) {
            return { success: false, error: 'Key not found in vault.' };
        }

        try {
            const payload = Buffer.from(this.#store.get(key), 'hex');

            // --- KMS/HSM Integration Point ---
            // For ultra-high security operations, instead of using the locally derived key,
            // the encrypted payload could be sent to a KMS/HSM for decryption.
            // The HSM would hold the master key and perform the decryption after
            // verifying its own access policies (e.g., M-of-N approvals).
            // Example:
            // const decrypted = await KmsService.decrypt({ payload, keyId: 'master-key-alias' });

            // Extract the components from the stored payload
            const iv = payload.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
            const authTag = payload.slice(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);
            const encryptedValue = payload.slice(SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);

            const decipher = createDecipheriv('aes-256-gcm', this.#derivedKey, iv);
            decipher.setAuthTag(authTag);

            const decryptedValue = Buffer.concat([decipher.update(encryptedValue), decipher.final()]).toString('utf8');

            return { success: true, data: decryptedValue };
        } catch (error) {
            // This catch block will be hit if the auth tag is invalid (tampering)
            // or if the key is incorrect.
            console.error('Decryption failed:', error);
            return { success: false, error: 'Decryption failed. The data may be corrupt or the key is incorrect.' };
        }
    }
}

// Export a single instance of the vault to act as a singleton.
// In a larger application, you might manage this instance differently.
export const vault = new Vault();
