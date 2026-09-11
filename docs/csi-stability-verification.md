# CSI stability remediation verification

## Finding-to-fix evidence

| Audit finding | Implementation | Regression evidence |
| --- | --- | --- |
| 1. Stale reconciliation can undo fencing/prune new attachment | `csi/pkg/driver/{attachments,reconcile}.go`, `crates/greendotctl/src/csi.rs`: persisted generation ownership and tombstones; exact-generation mutation | `TestGenerationReconcileSchedules`, `TestAttachmentLookupAndDelayedDetach`, `durable_generations_fence_stale_requests_and_preserve_new_owners` |
| 2. Multiple target owners | Atomic target publish/unpublish and exclusive host grants in `csi.rs` / `nvmet.rs` | Durable-generation test and existing nvmet lifecycle test |
| 3. Unbounded SSH/reconcile stalls | Context-aware transport ownership in `csi/pkg/helper/ssh.go`, keepalive in `client.go`, bounded reconcile operations | `TestTunnelRecovery`, reconcile continuation schedule |
| 4. Detached expansion | Managed dataset resolution independent of namespace in `nvmet.rs` | `csi_expand_detached_and_partial_failure_retries`; VM detached grow assertion |
| 5. Partial expansion skips revalidation | Controller always invokes target expansion; target always revalidates enabled namespace without shrinking | Same Rust expansion test, controller expansion table, VM online repeated grow |
| 6. Partial restore cannot resume | ZFS clone creation provenance and monotonic verified retries in `zfs.rs` | `restore_retries_verify_provenance_and_only_grow`, controller create table |
| 7. Raw-block mount stacking | Mount identity/readonly checks and serialization in `csi/pkg/node/node.go` | `TestPublishRetries`, `TestBlockMountIdentity`; VM repeated publish/count/cleanup |
| 8. Oversized derived identifiers | Early managed/imported NQN validation in controller; legacy unexportable managed-ID cleanup | Controller identifier boundary table and delete coverage |
| 9. VM test expects eager exports | `nix/vm-test-csi.nix` uses explicit attachment generation and asserts absent export after create/detach | Passed disposable real-kernel VM lifecycle test |
| Missing-volume sanity failure | Controller existence check and fake export existence checks | Documented sanity invocation now passes |

## Executed checks

- `go -C csi test -mod=readonly ./...`: passed.
- `go -C csi test -mod=readonly -race ./...`: passed.
- `go -C csi test -mod=readonly -tags sanity ./sanity -args '-ginkgo.skip=Node Service|different source volume ID|should fail when the node does not exist'`: passed with existing exclusions, no additional skips.
- `nix develop -c cargo test -p greendotctl -p greendot-proto`: 246 proto tests, 120 helper tests, and six socket tests passed; one existing ignored doctest. Existing socket tests attempt startup module loading, which this unprivileged environment rejects; those warnings did not fail the tests and do not establish kernel transport functionality.
- Regenerated protobuf Go/grpc files into a temporary directory using repository-pinned Nix tools and compared both files byte-for-byte: identical.
- `git diff --check`: clean at verification time.
- Nix expression parse and embedded VM Python AST parse: passed.

## Kernel coverage and remaining limits

The updated disposable VM test covers lazy export lifecycle, detached and online capacity growth, repeated raw-block publishing with mount count and cleanup, target-daemon restart followed by same-generation re-publish and actual initiator reads, rejection of a fenced generation, and real ext4 node expansion with preserved data. The e2e CLI exposes the required node stage/publish/unpublish/unstage/expand actions.

The user explicitly approved disposable VM execution and the one stale `flake.nix` vendor hash update required to build the current dependency closure (`sha256-Ow86098KdlVED84cvUxJB+NGoG88GxIbiRJaKaQrX2Y=`). The final `vmTestCsi` build **passed** after the real-kernel filesystem case exposed and the expansion task fixed multipath controller-rescan resolution. The namespace device link resolves to an NVMe subsystem, not directly to a controller; the implementation now follows actual controller membership rather than guessing controller zero. The unchanged filesystem growth/data-preservation assertion passed with that fix.

The original lazy-detach assertion also assumed immediate device disappearance. Real RDMA initiators retain a reconnecting device until controller-loss timeout when the listener is removed. The test now proves a non-live controller, failed bounded direct I/O, rejected reconnect and absent export rather than waiting for immediate udev removal. All test VMs were cleaned up by the Nix test driver.

The build used a temporary source snapshot including untracked implementation files, excluding only `.git`, `target` and `.tmp`; direct `path:.` input was rejected because existing build output contains a Unix socket. Final successful derivation: `/nix/store/ic4pndv1ahl4jpzk9jv2izrw4nylrlxq-vm-test-run-greendot-vm-csi.drv`; test script completed in 37.17 seconds (112 seconds including build). There is no production deployment or live-cluster validation here. A daemon restart is not a full target reboot: recovery after configfs loss, reconnect expiry and full target reboot remains unproven by these executed checks. Restore interruption is covered by injected unit-state failures, not a live ZFS fault-injection run.

No volume identifiers were migrated, production resources touched, commits made, or existing failed tests hidden. Review persistent attachment-state backup/recovery and upgrade ordering in `csi/README.md` before rollout.
