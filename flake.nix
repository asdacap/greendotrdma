{
  description = "GreenDotRDMA dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { self, nixpkgs }:
    let
      forAllSystems = f:
        nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ]
          (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            pkg-config
            cargo-deb
            patchelf # retarget release binaries onto Ubuntu's loader for the .deb
          ];

          buildInputs = with pkgs; [
            linux-pam # pam crate links libpam
          ];
        };
      });
    };
}
