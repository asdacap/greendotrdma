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

      # End-to-end tests in booted NixOS VMs against a real kernel: ZFS,
      # nvmet/LIO configfs, Soft-RoCE.
      #   nix build .#checks.x86_64-linux.vmTest -L         (single-node loopback)
      #   nix build .#checks.x86_64-linux.vmTestTwoNode -L  (cross-host RDMA + iSER)
      checks = forAllSystems (system: pkgs:
        nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          vmTest = import ./nix/vm-test.nix {
            inherit pkgs;
            greendot = self.packages.${system}.greendot;
          };
          vmTestTwoNode = import ./nix/vm-test-two-node.nix {
            inherit pkgs;
            greendot = self.packages.${system}.greendot;
          };
        });

      # Full real-kernel Ubuntu VM test: builds the .deb, boots an Ubuntu cloud
      # image under qemu, installs it, and exercises the green-dot flow + a real
      # `nvme connect -t rdma`. NON-HERMETIC (downloads the image, wants KVM), so
      # it's an app, NOT part of `nix flake check`. Run: nix run .#ubuntuVmTest
      apps = forAllSystems (system: pkgs:
        nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          ubuntuVmTest = {
            type = "app";
            program = "${pkgs.runCommand "greendot-ubuntu-vm-test"
              { nativeBuildInputs = [ pkgs.makeWrapper ]; } ''
              mkdir -p $out/bin
              cp ${./scripts/ubuntu-vm-test.sh} $out/bin/greendot-ubuntu-vm-test
              chmod +x $out/bin/greendot-ubuntu-vm-test
              patchShebangs $out/bin
              wrapProgram $out/bin/greendot-ubuntu-vm-test --prefix PATH : ${
                pkgs.lib.makeBinPath (with pkgs; [
                  qemu cloud-utils cdrkit openssh wget curl coreutils gnused gawk nix
                ])
              }
            ''}/bin/greendot-ubuntu-vm-test";
          };
        });
    };
}
