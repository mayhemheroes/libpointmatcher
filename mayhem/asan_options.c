/*
 * libpointmatcher/mayhem/asan_options.c — ASan runtime option overrides.
 *
 * LeakSanitizer (LSan) is enabled by default when ASan is built with
 * -fsanitize=address on Linux.  LSan works by fork()ing the target process and
 * ptrace-scanning the child.  Mayhem's coverage-collection mode ALREADY runs the
 * target under ptrace, so when LSan tries to fork+ptrace again it fails with
 * "ERROR: LeakSanitizer: ptrace(PTRACE_ATTACH, …) failed" and the process aborts
 * — producing 0 edges even when the code path is perfectly reachable.
 *
 * The fix: export detect_leaks=0 via __asan_default_options so LSan is compiled-in
 * but never activated at runtime.  All high-value detectors (heap overflow,
 * use-after-free, UBSan) remain active.
 *
 * Strong definition (no __attribute__((weak))) so it overrides any weak copy in
 * the ASan runtime or a linked instrumented shared library.
 */
const char *__asan_default_options(void)
{
    return "detect_leaks=0";
}
