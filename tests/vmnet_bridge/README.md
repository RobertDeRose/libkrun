# Native vmnet bridge tests

`./tests/vmnet_bridge/run.sh` compiles the production `src/libkrun/src/vmnet.c`
against the small vmnet/CF/XPC test doubles in this directory, with real dispatch
queues, Blocks, pthreads, and Unix datagram sockets. Run with `ASAN=1` for address
sanitization. Linux needs the Swift toolchain's libdispatch/BlocksRuntime; set
`SWIFT_LIBRARY_PATH` when they are installed elsewhere. macOS uses system dispatch.

These tests exercise raw frames in both directions, truncation rejection, static
subnet validation, shared-interface descriptor construction, serialized-network
compatibility, permission/start/event failures, resource release, and callbacks
arriving after timed-out start/stop calls. Timeout paths deliberately
retain uncertain framework resources until process exit; ASan leak reporting is
disabled for those tests, but use-after-free detection remains enabled.

The mocks are **not** macOS SDK declarations or an implementation of vmnet. These
tests cannot validate real framework permissions, reserved-network semantics,
Hypervisor.framework, or post-setuid network behavior. Compile and run the paired
container-runtime-krun native validator on macOS for that evidence.

Rust context/ABI tests are in `native_context_tests` in libkrun's `lib.rs`:

```
cargo test -p libkrun --features blk,net native_context_tests
```

The new `krun_create_ctx2(KRUN_CTX_NO_DEFAULT_FIRMWARE)` avoids default firmware
library discovery before privilege drop. Legacy `krun_create_ctx()` retains its
existing behavior. `krun_add_net_vmnet_shared()` is additive; the serialized API remains available.
The shared path uses `vmnet_start_interface()` so independent VMM processes can
join the same configured shared subnet, while the serialized path continues to
use `vmnet_interface_start_with_network()`. Both use the same packet bridge and
bounded callback handling.
