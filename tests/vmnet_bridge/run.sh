#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT
cc="${CC:-clang}"
flags=(-fblocks -std=c11 -D_DEFAULT_SOURCE -DKRUN_VMNET_TIMEOUT_MS=200   -Wall -Wextra -Werror)
libs=(-lpthread)
if [[ "$(uname -s)" == Linux ]]; then
  swift_lib="${SWIFT_LIBRARY_PATH:-$(cd "$(dirname "$(command -v swift)")/../lib/swift" && pwd -P)}"
  flags+=(-I"$swift_lib" -I"$swift_lib/Block")
  libs+=(-L"$swift_lib/linux" -Wl,-rpath,"$swift_lib/linux" -ldispatch -lBlocksRuntime)
fi
if [[ "${ASAN:-0}" == 1 ]]; then
  flags+=(-fsanitize=address -fno-omit-frame-pointer -g)
  # Timeout paths deliberately retain framework-owned resources until exit.
  export ASAN_OPTIONS=detect_leaks=0:halt_on_error=1
fi
"$cc" -I"$root/tests/vmnet_bridge/include" "${flags[@]}" \
  "$root/tests/vmnet_bridge/test_bridge.c" "${libs[@]}" -o "$build/test-bridge"
for scenario in success shared_pair serialized serialized_not_authorized invalid_arguments permission \
  null_interface_success start_failure invalid_packet_size event_failure \
  truncated_frame late_start late_stop stop_submit_failure; do
  "$build/test-bridge" "$scenario"
done
