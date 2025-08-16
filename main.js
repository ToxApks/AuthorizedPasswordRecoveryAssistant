// src/main.js

// Modules to control application life and create native browser window
import { app, BrowserWindow, ipcMain, dialog } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';

// ES Module compatibility for __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Creates the main application window.
 */
function createWindow() {
  // Create the browser window with secure webPreferences.
  const mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      // __dirname points to the root of the project in production builds
      // and to the 'src' folder in development.
      // path.join is used for platform compatibility.
      preload: path.join(__dirname, 'preload.js'),

      // contextIsolation is a critical security feature. It ensures that your preload
      // script and the renderer's JavaScript run in separate contexts.
      // This prevents web content from accessing Electron internals or powerful APIs.
      contextIsolation: true,

      // nodeIntegration should be false to prevent renderer processes from
      // accessing Node.js APIs directly, which is a major security risk.
      nodeIntegration: false,

      // enableRemoteModule is deprecated and insecure. It should be false.
      // Use IPC for communication between main and renderer processes.
      enableRemoteModule: false,
    },
  });

  // Load the index.html of the app.
  // In a real app, you might use a bundler like Webpack or Vite,
  // which would change this loading logic.
  mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));


  // Open the DevTools for debugging during development.
  if (process.env.NODE_ENV !== 'production') {
    mainWindow.webContents.openDevTools();
  }
}

// --- Application Lifecycle ---

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
app.whenReady().then(() => {
  createWindow();

  app.on('activate', function () {
    // On macOS it's common to re-create a window in the app when the
    // dock icon is clicked and there are no other windows open.
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// --- Secure IPC Handlers ---
// Use ipcMain.handle for two-way, async communication. This is generally
// safer and more modern than ipcMain.on.

/**
 * Handles a request to scan a resource.
 * This is a placeholder for a less sensitive operation.
 */
ipcMain.handle('request-scan', async (event, scanOptions) => {
  console.log('Received scan request with options:', scanOptions);

  // --- Audit Logging Point ---
  // This is where you would log the scan request event to your audit trail.
  // Example: auditLogger.log('SCAN_REQUESTED', { user: 'currentUser', options: scanOptions });
  // ---------------------------

  try {
    // Simulate an asynchronous operation like a network request or file system scan.
    const results = await new Promise(resolve => {
      setTimeout(() => {
        resolve({
          id: `scan_${Date.now()}`,
          status: 'completed',
          found: Math.floor(Math.random() * 10),
        });
      }, 1500);
    });

    // --- Audit Logging Point ---
    // Log the successful outcome.
    // Example: auditLogger.log('SCAN_SUCCEEDED', { results });
    // ---------------------------

    return { success: true, data: results };
  } catch (error) {
    console.error('Scan failed:', error);

    // --- Audit Logging Point ---
    // Log the failure.
    // Example: auditLogger.error('SCAN_FAILED', { error: error.message });
    // ---------------------------

    return { success: false, error: 'The scan operation failed.' };
  }
});

/**
 * Handles a request to access vaulted credentials or secrets.
 * This function explicitly denies direct access and enforces an approval workflow.
 */
ipcMain.handle('request-vault', async (event, vaultRequest) => {
  console.log('Received vault access request for:', vaultRequest.itemId);

  // --- Audit Logging Point ---
  // CRITICAL: Log every attempt to access sensitive data.
  // Example: auditLogger.warn('VAULT_ACCESS_ATTEMPTED', { user: 'currentUser', item: vaultRequest.itemId });
  // ---------------------------

  // SECURITY: This is the critical gatekeeper function.
  // It should NEVER return decrypted secrets directly.
  // The main process acts as a broker, not a key holder.

  // --- KMS/HSM Integration Point ---
  // Instead of decrypting here, the logic would typically involve:
  // 1. Verifying an existing, valid approval token for this specific request.
  // 2. If valid, making a request to a Key Management Service (KMS) or
  //    Hardware Security Module (HSM) to perform the decryption.
  // 3. The KMS/HSM would have its own strict access policies.
  // 4. The main process should never handle the raw private keys itself.
  // ---------------------------------

  // Return an explicit error indicating that direct access is forbidden and
  // an approval is required. This forces the renderer to use the proper workflow.
  return {
    success: false,
    error: 'Direct vault access is prohibited. An approval is required to proceed.',
    requiresApproval: true,
  };
});

/**
 * Handles a request for approval to perform a sensitive action.
 */
ipcMain.handle('request-approval', async (event, approvalDetails) => {
  console.log('Received approval request:', approvalDetails);

  // --- Audit Logging Point ---
  // Log the initiation of a sensitive workflow.
  // Example: auditLogger.log('APPROVAL_REQUESTED', { user: 'currentUser', details: approvalDetails });
  // ---------------------------

  try {
    // In a real system, this would trigger a workflow:
    // - Generate a unique, signed request token.
    // - Send a notification to an approver (e.g., via email, Slack, or another system).
    // - Store the pending request in a database with an expiry time.
    // For this example, we'll just simulate the request being logged.

    const approvalId = `approval_${Date.now()}`;
    console.log(`Approval workflow started with ID: ${approvalId}`);

    // Show a native dialog to the user to inform them.
    // This provides clear feedback that a sensitive process has started.
    dialog.showMessageBox({
      type: 'info',
      title: 'Approval Required',
      message: 'A request for approval has been sent.',
      detail: `Your request to "${approvalDetails.action}" requires review. You will be notified once it is approved or denied.`,
    });

    return { success: true, data: { approvalId, status: 'pending' } };
  } catch (error) {
    console.error('Approval request failed:', error);

    // --- Audit Logging Point ---
    // Log the failure to initiate the approval.
    // Example: auditLogger.error('APPROVAL_FAILED', { error: error.message });
    // ---------------------------

    return { success: false, error: 'Could not initiate the approval process.' };
  }
});
