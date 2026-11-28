//! Asking the processor for data-independent timing.
//!
//! The arithmetic in this crate is branch-free at source level, but a processor may still take
//! a different time for the same instruction on different operands. `tests/timing.rs` measured
//! that on an Apple M3: the response round ran about 0.6% faster for an all-zero share than
//! for one at the bound. Setting the DIT bit reduced the difference and did not remove it
//! (DECISIONS.md D-143). Every function that computes on a share, a mask or a key part sets
//! the bit first, and a party says at startup whether it could ([`report`]).

/// Set data-independent timing for the current thread, where the processor offers it.
/// Returns whether it is now on. The bit is per thread and stays set.
///
/// arm64 with the DIT feature only. On x86-64 the equivalent (DOITM) can be set only by the
/// operating system, so this returns `false` there.
#[inline]
pub fn harden_thread() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("dit") {
            // `msr dit, #1`, spelled as its encoding so that it assembles for any target CPU.
            unsafe { std::arch::asm!(".inst 0xd503415f", options(nomem, nostack)) };
            return true;
        }
    }
    false
}

/// One line for a party to print at startup: whether this processor's timing protection is
/// on, and if not, why. Sets it for the calling thread as a side effect.
pub fn report() -> (bool, &'static str) {
    if harden_thread() {
        return (true, "data-independent timing is on (arm64 DIT)");
    }
    if cfg!(target_arch = "aarch64") {
        (
            false,
            "data-independent timing is NOT available: this processor has no DIT",
        )
    } else if cfg!(target_arch = "x86_64") {
        (
            false,
            "data-independent timing is NOT set: on x86-64 only the operating system can set it (DOITM)",
        )
    } else {
        (
            false,
            "data-independent timing is NOT available on this architecture",
        )
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn hardening_a_thread_is_safe_to_repeat() {
        let first = super::harden_thread();
        assert_eq!(first, super::harden_thread());
        #[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
        assert!(first, "Apple silicon has DIT");
    }

    #[test]
    fn the_report_agrees_with_the_bit() {
        let (on, line) = super::report();
        assert_eq!(on, super::harden_thread());
        assert_eq!(on, !line.contains("NOT"));
    }
}
