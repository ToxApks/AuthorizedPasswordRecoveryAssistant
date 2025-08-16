// src/auditLogger.js

/**
 * @module auditLogger
 * This module provides a secure, append-only audit logging system. It writes logs
 * to a file and uses a hash chain to create a tamper-evident trail. Each log entry's
 * checksum is calculated using the checksum of the previous entry, making it
 * computationally infeasible to modify or delete a log without invalidating the
 * entire chain that follows.
 */

import fs from 'fs/promises';
import path from 'path';
import { createHash } from 'crypto';

// --- Configuration ---
// In a real application, this path should be configurable and point to a secure,
// persistent location within the application's data directory.
const LOG_FILE_PATH = path.join(process.cwd(), 'audit.log');
const HASH_ALGORITHM = 'sha256';
const GENESIS_HASH = '0'.repeat(64); // The checksum for the very first log entry.

/**
 * Calculates a SHA256 hash of a given string.
 * @param {string} data - The data to hash.
 * @returns {string} The hex-encoded hash.
 */
function createChecksum(data) {
    return createHash(HASH_ALGORITHM).update(data).digest('hex');
}

/**
 * Retrieves the last line of a file.
 * This is an efficient way to get the last log entry without reading the entire file.
 * @param {string} filePath - The path to the file.
 * @returns {Promise<string|null>} The last line of the file, or null if empty.
 */
async function getLastLine(filePath) {
    try {
        const fileHandle = await fs.open(filePath, 'r');
        const stats = await fileHandle.stat();
        if (stats.size === 0) {
            await fileHandle.close();
            return null;
        }

        // Read a chunk from the end of the file.
        const bufferSize = Math.min(1024, stats.size);
        const buffer = Buffer.alloc(bufferSize);
        await fileHandle.read(buffer, 0, bufferSize, stats.size - bufferSize);
        await fileHandle.close();

        const lines = buffer.toString('utf-8').trim().split('\n');
        return lines[lines.length - 1];
    } catch (error) {
        if (error.code === 'ENOENT') {
            return null; // File doesn't exist yet, which is fine.
        }
        throw error;
    }
}

/**
 * Appends a new entry to the audit log.
 *
 * @param {object} entry - The log entry details.
 * @param {string} entry.userId - The ID of the user performing the action.
 * @param {string} entry.action - The type of action (e.g., 'LOGIN', 'VAULT_ACCESS_REQUEST').
 * @param {string} entry.target - The resource being acted upon (e.g., 'itemId: key_123').
 * @param {string} [entry.reason] - The justification for the action.
 * @param {'SUCCESS'|'FAILURE'|'PENDING'} entry.outcome - The result of the action.
 * @returns {Promise<{success: boolean, error?: string}>}
 */
export async function appendLog(entry) {
    if (!entry || !entry.userId || !entry.action || !entry.target || !entry.outcome) {
        return { success: false, error: 'Log entry is missing required fields.' };
    }

    try {
        const lastLine = await getLastLine(LOG_FILE_PATH);
        const previousChecksum = lastLine ? JSON.parse(lastLine).checksum : GENESIS_HASH;

        const logRecord = {
            timestamp: new Date().toISOString(),
            ...entry,
            previousChecksum,
        };

        // The checksum is calculated over the canonical string representation of the log,
        // *excluding* the checksum field itself.
        const dataToHash = JSON.stringify(logRecord);
        logRecord.checksum = createChecksum(dataToHash);

        const logLine = JSON.stringify(logRecord) + '\n';

        // --- Log Retention & Exporting ---
        // In a production environment, logs should be periodically rotated, archived,
        // and exported to a centralized logging system (e.g., ELK stack, Splunk, SIEM).
        // This prevents local files from growing indefinitely and ensures long-term,
        // secure storage.
        await fs.appendFile(LOG_FILE_PATH, logLine, 'utf-8');

        return { success: true };
    } catch (error) {
        console.error('Failed to write to audit log:', error);
        return { success: false, error: 'Could not write to the audit log.' };
    }
}

/**
 * Queries the log file and filters entries. Also validates the hash chain integrity.
 *
 * @param {object} [filters={}] - Optional filters to apply.
 * @param {string} [filters.userId] - Filter by user ID.
 * @param {string} [filters.action] - Filter by action type.
 * @returns {Promise<{logs: object[], isValid: boolean, error?: string}>} The query results and integrity status.
 */
export async function queryLogs(filters = {}) {
    try {
        const data = await fs.readFile(LOG_FILE_PATH, 'utf-8');
        const lines = data.trim().split('\n');
        const logs = lines.map(line => JSON.parse(line));

        // --- Integrity Validation ---
        let previousChecksum = GENESIS_HASH;
        for (const log of logs) {
            const { checksum, ...recordWithoutChecksum } = log;
            const expectedChecksum = createChecksum(JSON.stringify(recordWithoutChecksum));
            if (checksum !== expectedChecksum || recordWithoutChecksum.previousChecksum !== previousChecksum) {
                return { logs: [], isValid: false, error: 'Log tampering detected!' };
            }
            previousChecksum = checksum;
        }

        const filteredLogs = logs.filter(log => {
            return Object.entries(filters).every(([key, value]) => log[key] === value);
        });

        return { logs: filteredLogs, isValid: true };
    } catch (error) {
        if (error.code === 'ENOENT') {
            return { logs: [], isValid: true }; // No log file means no logs, but it's a valid state.
        }
        console.error('Failed to query audit logs:', error);
        return { logs: [], isValid: false, error: 'Could not read or parse the audit log.' };
    }
}
