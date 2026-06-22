# Shared building blocks for the NixOS VM tests (single-node vm-test.nix and
# two-node vm-test-two-node.nix): the patched CLIs the services shell out to,
# the test config, and a module that runs the full greendot stack on a node.
{ pkgs }:

let
  # NVMe-oF needs no external tool: the helper writes its nvmet configfs tree
  # directly. Only the iSCSI apply path still shells out (to `targetctl`).
  #
  # The iSCSI apply path runs `targetctl restore`. nixpkgs' `targetcli-fb`
  # ships only `targetcli`, not the `targetctl` helper — but `rtslib-fb` ships
  # the very same `targetctl` Ubuntu uses (restore clears the existing config
  # then applies, so disabled exports are torn down). Use it directly.
  targetctl = pkgs.python3Packages.rtslib-fb;

  # The CLIs the services shell out to. On Ubuntu these are on the default
  # systemd PATH (/usr/bin etc.); on NixOS we put them on the service `path`.
  # `nfs-utils` provides `exportfs` and `pkgs.systemd` provides `systemctl` for
  # the NFS apply path (start nfs-server, exportfs the share).
  tools = [
    targetctl
    pkgs.zfs
    pkgs.kmod
    pkgs.rdma-core
    pkgs.util-linux
    pkgs.nvme-cli
    pkgs.nfs-utils
    pkgs.systemd
  ];

  configToml = pkgs.writeText "greendot-config.toml" ''
    listen = "127.0.0.1:8080"
    helper_socket = "/run/greendotrdma/helper.sock"
    db_path = "/var/lib/greendotrdma/state.db"
    metrics_db_path = "/var/lib/greendotrdma/metrics.db"
    nvmet_root = "/sys/kernel/config/nvmet"
    lio_root = "/sys/kernel/config/target"
    # plain HTTP for the test so curl stays simple; production defaults to TLS
  '';

  # A NixOS module for a node running the full greendot stack (the export
  # target). `extraKernelModules` lets the two-node target pull in the
  # iSCSI/iSER target modules on top of the NVMe-oF set.
  mkGreendotNode = { greendot, extraKernelModules ? [ ] }:
    { config, pkgs, lib, ... }: {
      virtualisation.memorySize = 3072;
      virtualisation.cores = 4;

      # Storage / RDMA stack.
      boot.supportedFilesystems = [ "zfs" ];
      networking.hostId = "deadbeef";
      # Let initiators reach the export ports / RoCE traffic across the test LAN.
      networking.firewall.enable = false;
      boot.kernelModules = [
        "configfs"
        "nvmet"
        "nvme_fabrics"
        "nvme_loop"
        "nvmet_tcp"
        "nvmet_rdma"
        "nvme_rdma"
        "rdma_rxe"
        # NFS-over-RDMA server transport (svcrdma/xprtrdma alias `rpcrdma`).
        "rpcrdma"
      ] ++ extraKernelModules;
      # The NFS server: provides nfsd + the `nfs-server` unit greendot starts,
      # and `exportfs`/`mount.nfs`. greendot manages only its own exports file.
      services.nfs.server.enable = true;
      environment.systemPackages = with pkgs; [
        greendot
        nvme-cli
        targetctl # targetcli-fb; the iSCSI apply task shells out to targetctl
        rdma-core
        util-linux
        curl
        zfs
        nfs-utils
      ];

      # Accounts: the service user/group and an admin login.
      users.groups.greendot = { };
      users.users.greendot = {
        isSystemUser = true;
        group = "greendot";
        home = "/var/lib/greendotrdma";
      };
      users.groups.greendot-admin = { };
      users.users.gdadmin = {
        isNormalUser = true;
        password = "test";
        extraGroups = [ "greendot-admin" ];
      };
      users.users.gduser = {
        # a valid system user who is NOT in greendot-admin
        isNormalUser = true;
        password = "test";
      };

      # PAM service the helper authenticates against (matches pam_service default).
      security.pam.services.greendotrdma = { };

      systemd.services.greendot-helper = {
        description = "GreenDotRDMA privileged helper";
        wantedBy = [ "multi-user.target" ];
        path = tools;
        serviceConfig = {
          ExecStart = "${greendot}/bin/greendot-helper";
          Restart = "on-failure";
          RuntimeDirectory = "greendotrdma";
          RuntimeDirectoryMode = "0755";
        };
      };

      systemd.services.greendot-web = {
        description = "GreenDotRDMA web UI";
        wantedBy = [ "multi-user.target" ];
        after = [ "greendot-helper.service" ];
        path = tools;
        serviceConfig = {
          User = "greendot";
          Group = "greendot";
          ExecStart = "${greendot}/bin/greendot-web ${configToml}";
          Restart = "on-failure";
          StateDirectory = "greendotrdma";
        };
      };
    };
in
{
  inherit targetctl tools configToml mkGreendotNode;
}
