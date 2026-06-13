{
  description = "GreenDotRDMA — easy NVMe-oF/iSCSI exports over RDMA";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { self, nixpkgs }:
    let
      forAllSystems = f:
        nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ]
          (system: f system nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (system: pkgs: {
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

      # Native nix build of both binaries. They link the nix store, so they
      # run on NixOS (used by the VM test below); the Ubuntu .deb is built
      # separately via scripts/build-deb.sh.
      packages = forAllSystems (system: pkgs: {
        greendot = pkgs.rustPlatform.buildRustPackage {
          pname = "greendot";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.linux-pam ];
          doCheck = false; # unit tests run in the dev shell; this is just the binaries
        };
      });

      # End-to-end test in a booted NixOS VM against a real kernel: ZFS,
      # nvmet/LIO configfs, Soft-RoCE. Run: nix build .#checks.x86_64-linux.vmTest -L
      checks = forAllSystems (system: pkgs:
        nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          vmTest = import ./nix/vm-test.nix {
            inherit pkgs;
            greendot = self.packages.${system}.greendot;
          };
        });
    };
}
