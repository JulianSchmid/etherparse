use core::cell::Cell;
use std::alloc::{GlobalAlloc, Layout, System};

/// Allocator of the unit tests that counts the allocations of each thread
/// (see [`count_allocations`]).
struct CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

std::thread_local! {
    /// Number of allocations and reallocations the thread made.
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

/// Counts an allocation or reallocation of the current thread.
fn count() {
    // the counter is gone while the thread exits
    let _ = ALLOCATIONS.try_with(|allocations| allocations.set(allocations.get() + 1));
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: the caller upholds the contract of `GlobalAlloc::alloc`.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: the caller upholds the contract of
        // `GlobalAlloc::alloc_zeroed`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count();
        // SAFETY: the caller upholds the contract of `GlobalAlloc::realloc`,
        // and `ptr` was allocated by `System`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller upholds the contract of `GlobalAlloc::dealloc`,
        // and `ptr` was allocated by `System`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// Runs `f` and returns the number of allocations and reallocations it made
/// on the current thread, together with its result.
pub(crate) fn count_allocations<R>(f: impl FnOnce() -> R) -> (u64, R) {
    let before = ALLOCATIONS.with(Cell::get);
    let result = f();
    (ALLOCATIONS.with(Cell::get) - before, result)
}

#[cfg(test)]
mod test {
    use std::{vec, vec::Vec};

    #[test]
    fn count_allocations() {
        // nothing allocated
        assert_eq!((0, 5), super::count_allocations(|| 5));

        // allocations, zeroed allocations and reallocations count,
        // deallocations don't
        let (allocations, ()) = super::count_allocations(|| {
            let mut buf = Vec::<u8>::with_capacity(1);
            buf.reserve_exact(2);
            let zeroed = vec![0u8; 8];
            drop(buf);
            drop(zeroed);
        });
        assert_eq!(3, allocations);
    }
}
