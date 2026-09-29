#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT
cc="${CC:-clang}"
flags=(-fblocks -std=c11 -D_DEFAULT_SOURCE -DKRUN_VMNET_TIMEOUT_MS=200   -Wall -Wextra -Werror)
libs=(-lpthread)

select_macos_sdk() {
  local probe_src="$build/sdk-probe.c"
  local probe_bin="$build/sdk-probe"
  local probe_err="$build/sdk-probe.err"
  local -a candidates=()
  local sdk

  printf 'int main(void) { return 0; }\n' >"$probe_src"
  if [[ -n "${SDKROOT:-}" ]]; then
    candidates+=("$SDKROOT")
  fi
  if [[ -d /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs ]]; then
    while IFS= read -r sdk; do
      candidates+=("$sdk")
    done < <(find /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs \
      -maxdepth 1 -type d -name 'MacOSX*.sdk' -print)
  fi
  if command -v xcrun >/dev/null 2>&1; then
    sdk="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
    [[ -n "$sdk" ]] && candidates+=("$sdk")
  fi
  if [[ -d /Library/Developer/CommandLineTools/SDKs ]]; then
    while IFS= read -r sdk; do
      candidates+=("$sdk")
    done < <(find /Library/Developer/CommandLineTools/SDKs \
      -maxdepth 1 -type d -name 'MacOSX*.sdk' -print)
  fi

  local seen=':'
  for sdk in "${candidates[@]}"; do
    [[ -d "$sdk" ]] || continue
    case "$seen" in
      *":$sdk:"*) continue ;;
    esac
    seen+="$sdk:"
    if "$cc" -isysroot "$sdk" "$probe_src" -o "$probe_bin" > /dev/null 2>"$probe_err"; then
      printf '%s\n' "$sdk"
      return 0
    fi
  done

  echo "vmnet bridge tests: no installed macOS SDK can be linked by $cc" >&2
  if [[ -s "$probe_err" ]]; then
    cat "$probe_err" >&2
  fi
  return 1
}

if [[ "$(uname -s)" == Darwin ]]; then
  macos_sdk="$(select_macos_sdk)"
  flags+=(-isysroot "$macos_sdk")
  echo "vmnet bridge tests: using macOS SDK $macos_sdk" >&2
fi
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
for scenario in socket_recv_batch success offload large_tx_batch batched_io partial_write batch_cap \
  shared_pair serialized serialized_offload serialized_not_authorized invalid_arguments permission \
  null_interface_success start_failure invalid_packet_size event_failure \
  truncated_frame late_start late_stop stop_submit_failure; do
  "$build/test-bridge" "$scenario"
done
