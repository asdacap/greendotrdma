// Thin shell: every action shells out to `greendot-client --json <args>` and
// returns its parsed JSON. All intelligence (and all privilege, via the root
// agent) lives in the CLI; the GUI renders opaque strings.
//
// Dev run: GREENDOT_CLIENT_BIN=../../target/debug/greendot-client npx electron .

const { app, BrowserWindow, ipcMain } = require("electron");
const { execFile } = require("node:child_process");
const path = require("node:path");

const BIN = process.env.GREENDOT_CLIENT_BIN || "greendot-client";

function runCli(args) {
  return new Promise((resolve) => {
    execFile(
      BIN,
      ["--json", ...args],
      { timeout: 120_000, maxBuffer: 4 * 1024 * 1024 },
      (error, stdout, stderr) => {
        // The CLI prints {"ok":false,"error":...} JSON on failure; fall back
        // to stderr/exec errors (binary missing, timeout) as the same shape.
        try {
          resolve(JSON.parse(stdout));
        } catch {
          resolve({
            ok: false,
            error:
              (error && error.code === "ENOENT"
                ? `greendot-client not found (${BIN}) — install the greendot-client package`
                : stderr.trim() || (error && error.message)) || "unknown error",
          });
        }
      },
    );
  });
}

// The renderer sends an argv array; reject anything that isn't plain strings.
ipcMain.handle("cli", (_event, args) => {
  if (!Array.isArray(args) || !args.every((a) => typeof a === "string")) {
    return { ok: false, error: "bad invoke" };
  }
  return runCli(args);
});

app.whenReady().then(() => {
  const win = new BrowserWindow({
    width: 1000,
    height: 720,
    backgroundColor: "#11191f",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.loadFile("index.html");
});

app.on("window-all-closed", () => app.quit());
