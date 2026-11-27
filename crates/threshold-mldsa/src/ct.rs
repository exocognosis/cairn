//! Asking the processor for data-independent timing.
//!
//! The arithmetic in this crate is branch-free at source level, but a processor may still take
//! a different time for the same instruction on different operands. `tests/timing.rs` measured
//! that on an Apple M3: the response round ran about 0.6% faster for an all-zero share than
//! for one at the bound, and the difference went away with the DIT bit set. So every thread
//! that handles a share or a mask sets it first.

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

#[cfg(test)]
mod tests {
    #[test]
    fn hardening_a_thread_is_safe_to_repeat() {
        let first = super::harden_thread();
        assert_eq!(first, super::harden_thread());
        #[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
        assert!(first, "Apple silicon has DIT");
    }
}
