# GreenDot Client GUI

A thin Electron shell over the `greendot-client` CLI: it renders
`greendot-client --json list` (targets, exports, client-side green dots) and
forwards Add target / Connect / Mount / Diagnose clicks back to the CLI. All
privilege stays in the CLI's root agent; the GUI never parses anything but
the CLI's JSON.

## Dev run

```sh
cd client/gui
npm install
GREENDOT_CLIENT_BIN=../../target/debug/greendot-client npx electron .
```

Without `GREENDOT_CLIENT_BIN` it runs `greendot-client` from PATH (the
installed package). On NixOS use an electron from nixpkgs
(`nix shell nixpkgs#electron -c electron .`) — the npm-downloaded binary
does not run unpatched.

Distribution packaging (electron-builder, .deb) is a later phase.
