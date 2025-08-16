// src/preload.js

import { contextBridge, ipcRenderer } from 'electron';

// --- Security Notice ---
// The preload script runs in a privileged environment that has access to Node.js APIs.
// However, it shares a window object with the renderer process.
// To prevent leaking powerful APIs to potentially untrusted web content,
// we use the `contextBridge`.

// `contextBridge.exposeInMainWorld` creates a secure, isolated bridge between
// the renderer's `window` object and this preload script. Only the functions
// explicitly defined here will be available to the renderer, and they will
// not have access to the Node.js context of this script.

contextBridge.exposeInMainWorld('recoveryAPI', {
  /**
   * Invokes the 'request-scan' IPC channel in the main process.
   * @param {string[]} folderPaths - An array of absolute folder paths to scan.
   * @returns {Promise<object>} A promise that resolves with the scan results.
   */
  requestScan: (folderPaths) => {
    // --- Argument Validation ---
    // It's crucial to validate and sanitize all arguments received from the
    // renderer process. This prevents malformed data from causing errors or
    // security vulnerabilities in the main process.
    if (!Array.isArray(folderPaths) || !folderPaths.every(p => typeof p === 'string' && p.length > 0)) {
      return Promise.reject(new Error('Invalid argument: folderPaths must be an array of non-empty strings.'));
    }
    return ipcRenderer.invoke('request-scan', folderPaths);
  },

  /**
   * Attempts to access a vaulted item, triggering the approval workflow.
   * This function will always be denied by the main process, which will
   * respond that an approval is needed.
   * @param {string} itemId - The ID of the item to access in the vault.
   * @returns {Promise<object>} A promise that resolves with the main process's response.
   */
  requestVaultAccess: (itemId) => {
    if (typeof itemId !== 'string' || itemId.length === 0) {
      return Promise.reject(new Error('Invalid argument: itemId must be a non-empty string.'));
    }
    return ipcRenderer.invoke('request-vault', { itemId });
  },

  /**
   * Invokes the 'request-approval' IPC channel to start a sensitive action workflow.
   * @param {object} approvalDetails - An object containing details for the approval request.
   * @returns {Promise<object>} A promise that resolves with the approval request status.
   */
  requestApproval: (approvalDetails) => {
    if (typeof approvalDetails !== 'object' || approvalDetails === null) {
      return Promise.reject(new Error('Invalid argument: approvalDetails must be an object.'));
    }
    return ipcRenderer.invoke('request-approval', approvalDetails);
  },

  /**
   * Submits an approval token to the main process.
   * NOTE: The 'submit-approval' handler is not yet implemented in main.js.
   * @param {string} token - The approval token received from the approval authority.
   * @returns {Promise<object>} A promise that resolves with the result of the submission.
   */
  submitApproval: (token) => {
    if (typeof token !== 'string' || token.length === 0) {
      return Promise.reject(new Error('Invalid argument: token must be a non-empty string.'));
    }
    // This channel needs a corresponding ipcMain.handle('submit-approval', ...) in main.js
    return ipcRenderer.invoke('submit-approval', token);
  },

  /**
   * Requests the main process to generate and export a recovery package.
   * NOTE: The 'export-recovery-package' handler is not yet implemented in main.js.
   * @returns {Promise<object>} A promise that resolves with the export status.
   */
  exportRecoveryPackage: () => {
    // This channel needs a corresponding ipcMain.handle('export-recovery-package', ...) in main.js
    return ipcRenderer.invoke('export-recovery-package');
  },
});
