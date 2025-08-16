// src/approvalWorkflow.js

/**
 * @module approvalWorkflow
 * This module manages the lifecycle of sensitive action approvals. It provides
 * an in-memory simulation of an M-of-N (e.g., 2-of-3) approval system.
 * It is designed with hooks for real-world integrations like notifications and SSO.
 */

import { randomBytes, createHmac } from 'crypto';

// --- In-Memory Request Store ---
// In a production system, this would be a persistent, secure database (e.g., SQL, Redis).
const pendingRequests = new Map();

// A secret key for signing tokens. In production, this MUST be loaded securely
// from an environment variable or a secret management service (e.g., Vault, AWS KMS).
// DO NOT hard-code this value.
const TOKEN_SECRET = process.env.APPROVAL_TOKEN_SECRET || 'default-super-secret-key-for-dev-only';

/**
 * Creates a new approval request for a sensitive action.
 *
 * @param {object} options - The details of the request.
 * @param {string} options.requesterId - The ID of the user making the request.
 * @param {string} options.action - A description of the action requiring approval (e.g., 'ACCESS_VAULT_ITEM').
 * @param {object} options.details - Any relevant data for the action (e.g., { itemId: 'key_123' }).
 * @param {number} [options.requiredApprovals=2] - The 'M' in M-of-N. The number of approvals needed.
 * @param {string[]} options.potentialApprovers - An array of user IDs who are eligible to approve.
 * @param {number} [options.ttl=3600] - Time-to-live for the request in seconds (defaults to 1 hour).
 * @returns {{success: boolean, requestId?: string, error?: string}} The result of the request creation.
 */
export function createRequest(options) {
    const { requesterId, action, details, requiredApprovals = 2, potentialApprovers, ttl = 3600 } = options;

    if (!requesterId || !action || !potentialApprovers || potentialApprovers.length < requiredApprovals) {
        return { success: false, error: 'Invalid request parameters. Ensure requester, action, and a valid set of approvers are provided.' };
    }

    const requestId = randomBytes(16).toString('hex');
    const expiresAt = Date.now() + ttl * 1000;

    const request = {
        id: requestId,
        requesterId,
        action,
        details,
        status: 'PENDING',
        requiredApprovals,
        potentialApprovers,
        approvals: [], // Stores { approverId, timestamp }
        createdAt: Date.now(),
        expiresAt,
    };

    pendingRequests.set(requestId, request);

    // --- Audit Logging Hook ---
    // Log the creation of this sensitive request immediately.
    // auditLogger.log('APPROVAL_REQUEST_CREATED', { requestId, requesterId, action });

    // --- Notification Hook ---
    // Trigger notifications to the potential approvers.
    // notificationService.notifyApprovers(potentialApprovers, { requestId, action, requesterId });

    return { success: true, requestId };
}

/**
 * Lists all currently pending approval requests.
 * In a real system, this would be access-controlled based on the user's role.
 * @returns {object[]} A list of pending request objects.
 */
export function listPendingApprovals() {
    return Array.from(pendingRequests.values())
        .filter(req => req.status === 'PENDING' && req.expiresAt > Date.now());
}

/**
 * Applies an approval to a specific request.
 *
 * @param {object} options
 * @param {string} options.requestId - The ID of the request to approve.
 * @param {string} options.approverId - The ID of the user granting approval.
 * @returns {{success: boolean, status?: string, error?: string}} The result of applying the approval.
 */
export function applyApproval({ requestId, approverId }) {
    const request = pendingRequests.get(requestId);

    // --- Validation and Edge Cases ---
    if (!request) {
        return { success: false, error: 'Request not found.' };
    }
    if (request.expiresAt <= Date.now()) {
        request.status = 'EXPIRED';
        return { success: false, error: 'Request has expired.' };
    }
    if (request.status !== 'PENDING') {
        return { success: false, error: `Request is no longer pending (status: ${request.status}).` };
    }

    // --- SSO / Auth Hook ---
    // Before proceeding, the approver's identity and authorization should be verified.
    // For example, check if `approverId` is in `request.potentialApprovers`.
    if (!request.potentialApprovers.includes(approverId)) {
        return { success: false, error: 'User is not authorized to approve this request.' };
    }
    if (request.approvals.some(a => a.approverId === approverId)) {
        return { success: false, error: 'User has already approved this request.' };
    }

    request.approvals.push({
        approverId,
        timestamp: Date.now(),
    });

    // --- Audit Logging Hook ---
    // auditLogger.log('APPROVAL_APPLIED', { requestId, approverId });

    // Check if the M-of-N condition is now met.
    if (request.approvals.length >= request.requiredApprovals) {
        request.status = 'APPROVED';
    }

    return { success: true, status: request.status };
}

/**
 * Checks the status of a request and, if fully approved, returns a time-limited token.
 *
 * @param {string} requestId - The ID of the request to check.
 * @returns {{status: string, token?: string, error?: string}} The current status and a token if approved.
 */
export function checkApprovalStatus(requestId) {
    const request = pendingRequests.get(requestId);

    if (!request) {
        return { status: 'NOT_FOUND', error: 'Request not found.' };
    }
    if (request.expiresAt <= Date.now() && request.status === 'PENDING') {
        request.status = 'EXPIRED';
    }

    if (request.status === 'APPROVED') {
        // --- Time-Limited Token Generation ---
        // Once approved, generate a short-lived, signed token (e.g., a JWT)
        // that the main process can use to authorize the final, sensitive action.
        const payload = JSON.stringify({
            sub: request.requesterId,
            req: requestId,
            act: request.action,
            // Expiry for the token itself (e.g., 5 minutes)
            exp: Date.now() + 300 * 1000,
        });
        const signature = createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex');
        const token = `${Buffer.from(payload).toString('base64url')}.${signature}`;

        // The request is now considered complete and can be removed.
        pendingRequests.delete(requestId);

        return { status: 'APPROVED', token: token };
    }

    return { status: request.status };
}
