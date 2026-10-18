/*
 * Minimal Darwin TargetConditionals.h shim for check-only cross-compilation of
 * the platform-macos closure (`--target aarch64-apple-darwin`) on Linux hosts.
 *
 * `ring` supports freestanding / sysroot-less C compilation when built with
 * `clang -nostdlibinc -DRING_CORE_NOSTDLIBINC=1` (see `ring/build.rs` and
 * `ring/include/ring-core/check.h`). Under `__APPLE__`, `ring`'s
 * `include/ring-core/base.h` still includes `<TargetConditionals.h>` solely to
 * branch on `TARGET_OS_OSX` vs `TARGET_OS_IPHONE`. Providing those macros here
 * lets `just cross-check-macos` compile the full `platform-macos` closure on
 * Linux without a proprietary macOS SDK or any crate exclusions.
 */
#ifndef CARRICK_DARWIN_CHECK_TARGETCONDITIONALS_H
#define CARRICK_DARWIN_CHECK_TARGETCONDITIONALS_H

#define TARGET_OS_MAC 1
#define TARGET_OS_OSX 1
#define TARGET_OS_IPHONE 0
#define TARGET_OS_IOS 0
#define TARGET_OS_WATCH 0
#define TARGET_OS_TV 0
#define TARGET_OS_SIMULATOR 0
#define TARGET_OS_EMBEDDED 0
#define TARGET_CPU_ARM64 1

#endif /* CARRICK_DARWIN_CHECK_TARGETCONDITIONALS_H */
