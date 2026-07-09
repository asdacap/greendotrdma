const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("greendot", {
  invoke: (args) => ipcRenderer.invoke("cli", args),
});
