// renderer/renderer.js

/**
 * This script runs in the renderer process. It has access to the DOM
 * but does NOT have direct access to Node.js or Electron APIs.
 * All communication with the main process must go through the secure
 * `window.recoveryAPI` object exposed by the preload script.
 */

// Wait for the DOM to be fully loaded before attaching event listeners.
document.addEventListener('DOMContentLoaded', () => {

    // --- DOM Element Selectors ---
    const intakeForm = document.getElementById('intake-form');
    const scanPathsInput = document.getElementById('scan-paths');
    const scanStatus = document.getElementById('scan-status');
    const resultsContainer = document.getElementById('results-container');
    const vaultItemsContainer = document.getElementById('vault-items');
    const approvalForm = document.getElementById('approval-form');
    const approvalItemIdInput = document.getElementById('approval-item-id');
    const approvalJustificationInput = document.getElementById('approval-justification');
    const requestApprovalBtn = document.getElementById('request-approval-btn');
    const approvalStatus = document.getElementById('approval-status');

    // --- Helper Functions ---

    /**
     * Updates a status display element with a message.
     * @param {HTMLElement} element - The DOM element to update.
     * @param {string} message - The text message to display.
     * @param {'info' | 'error' | 'success'} type - The type of message for styling.
     */
    function updateStatus(element, message, type = 'info') {
        element.textContent = message;
        element.style.color = type === 'error' ? 'var(--danger-color)' : (type === 'success' ? '#4ade80' : 'var(--text-muted-color)');
    }

    /**
     * Renders items discovered in the vault.
     * @param {Array<object>} items - An array of vault item objects.
     */
    function renderVaultItems(items) {
        // Clear placeholder
        vaultItemsContainer.innerHTML = '';

        if (!items || items.length === 0) {
            vaultItemsContainer.innerHTML = '<p>No vault items found in the scan.</p>';
            return;
        }

        items.forEach(item => {
            const itemEl = document.createElement('div');
            itemEl.className = 'vault-item';
            // Use data attributes to store metadata securely in the DOM.
            itemEl.setAttribute('data-item-id', item.id);

            const itemName = document.createElement('span');
            itemName.textContent = item.name; // e.g., "id_rsa" or "credentials.json"

            const requestBtn = document.createElement('button');
            requestBtn.textContent = 'Request Access';
            requestBtn.className = 'request-access-btn';

            itemEl.appendChild(itemName);
            itemEl.appendChild(requestBtn);
            vaultItemsContainer.appendChild(itemEl);
        });
    }


    // --- Event Listeners ---

    /**
     * Handles the submission of the initial scan request form.
     */
    intakeForm.addEventListener('submit', async (event) => {
        event.preventDefault(); // Prevent default form submission

        const pathsText = scanPathsInput.value.trim();
        if (!pathsText) {
            updateStatus(scanStatus, 'Error: Please provide at least one folder path to scan.', 'error');
            return;
        }

        // Split by newline and filter out empty lines
        const folderPaths = pathsText.split('\n').filter(p => p.trim() !== '');

        updateStatus(scanStatus, `Scanning ${folderPaths.length} location(s)...`, 'info');
        resultsContainer.innerHTML = '<p>Processing...</p>';

        try {
            const result = await window.recoveryAPI.requestScan(folderPaths);

            if (result.success) {
                updateStatus(scanStatus, `Scan completed successfully. Found ${result.data.found} items.`, 'success');
                // --- UI Hook ---
                // In a real app, you would parse result.data and display it.
                // For now, we'll just show the raw data and mock some vault items.
                resultsContainer.innerHTML = `<pre>${JSON.stringify(result.data, null, 2)}</pre>`;

                // Mock rendering vault items based on the scan
                const mockVaultItems = [
                    { id: 'vault_item_12345', name: 'SecretKey.dat' },
                    { id: 'vault_item_67890', name: 'user_credentials.json' }
                ];
                renderVaultItems(mockVaultItems);

            } else {
                throw new Error(result.error);
            }
        } catch (error) {
            console.error('Scan request failed:', error);
            updateStatus(scanStatus, `Error: ${error.message}`, 'error');
            resultsContainer.innerHTML = '<p>The scan could not be completed.</p>';
        }
    });

    /**
     * Handles clicks on dynamically generated "Request Access" buttons in the vault.
     * This uses event delegation to listen for clicks on the container.
     */
    vaultItemsContainer.addEventListener('click', async (event) => {
        if (event.target.classList.contains('request-access-btn')) {
            const vaultItem = event.target.closest('.vault-item');
            const itemId = vaultItem.dataset.itemId;

            updateStatus(approvalStatus, `Requesting access to ${itemId}...`, 'info');
            
            try {
                // --- SECURITY ---
                // This call is DESIGNED to fail and return a message that
                // directs the user to the approval workflow. We are never
                // attempting to get the secret directly.
                const result = await window.recoveryAPI.requestVaultAccess(itemId);

                if (result.requiresApproval) {
                    updateStatus(approvalStatus, `Approval is required for item: ${itemId}. Please fill out and submit the form below.`, 'info');
                    // Populate the approval form with the item ID
                    approvalItemIdInput.value = itemId;
                    approvalJustificationInput.focus();
                } else {
                    // This block should ideally never be reached based on main.js logic
                    throw new Error('Unexpected response from main process.');
                }

            } catch (error) {
                console.error('Vault access request failed:', error);
                updateStatus(approvalStatus, `Error: ${error.message}`, 'error');
            }
        }
    });

    /**
     * Handles the click on the "Request Approval" button.
     */
    requestApprovalBtn.addEventListener('click', async () => {
        const itemId = approvalItemIdInput.value;
        const justification = approvalJustificationInput.value.trim();

        if (!itemId || !justification) {
            updateStatus(approvalStatus, 'Error: You must select an item and provide a justification.', 'error');
            return;
        }

        updateStatus(approvalStatus, 'Submitting approval request...', 'info');

        try {
            const result = await window.recoveryAPI.requestApproval({
                action: `Access Vault Item: ${itemId}`,
                justification: justification,
            });

            if (result.success) {
                updateStatus(approvalStatus, `Approval request sent successfully. ID: ${result.data.approvalId}`, 'success');
                // Clear the form after successful submission
                approvalForm.reset();
            } else {
                throw new Error(result.error);
            }
        } catch (error) {
            console.error('Approval request failed:', error);
            updateStatus(approvalStatus, `Error: ${error.message}`, 'error');
        }
    });

    // --- Testing Note ---
    // To test this renderer logic without running the full Electron app,
    // you can create a mock `window.recoveryAPI` object in your test environment (e.g., Jest).
    // Example:
    // window.recoveryAPI = {
    //   requestScan: jest.fn().mockResolvedValue({ success: true, data: { found: 5 } }),
    //   requestVaultAccess: jest.fn().mockResolvedValue({ success: false, requiresApproval: true }),
    //   // ...etc
    // };
});
