#![allow(dead_code)] // Cache publication is wired into block emission in Task 4.

use std::ptr::NonNull;

use carrick_guest_mem::HostVa;

use super::types::{CacheVa, DsrError};

pub(super) struct PublishedCode {
    entry: CacheVa,
    len: usize,
}

impl PublishedCode {
    pub(super) const fn entry(&self) -> CacheVa {
        self.entry
    }

    pub(super) const fn len(&self) -> usize {
        self.len
    }
}

pub(super) struct TranslationCache {
    base: NonNull<u8>,
    capacity: usize,
    cursor: usize,
}

impl TranslationCache {
    pub(super) fn new(requested_capacity: usize) -> Result<Self, DsrError> {
        if requested_capacity == 0 {
            return Err(DsrError::CachePolicy(
                "translation cache capacity must be nonzero".to_string(),
            ));
        }
        if unsafe { libc::pthread_jit_write_protect_supported_np() } == 0 {
            return Err(DsrError::CachePolicy(
                "pthread JIT write protection is unavailable".to_string(),
            ));
        }
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            return Err(DsrError::Host {
                operation: "query host page size",
                error: std::io::Error::last_os_error(),
            });
        }
        let page_size = page_size as usize;
        let capacity = requested_capacity
            .checked_add(page_size - 1)
            .map(|value| value & !(page_size - 1))
            .ok_or_else(|| DsrError::CachePolicy("translation cache size overflow".to_string()))?;
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                capacity,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(DsrError::Host {
                operation: "allocate MAP_JIT translation cache",
                error: std::io::Error::last_os_error(),
            });
        }
        let base = NonNull::new(mapped.cast::<u8>())
            .ok_or_else(|| DsrError::CachePolicy("MAP_JIT returned a null mapping".to_string()))?;
        unsafe { libc::pthread_jit_write_protect_np(1) };
        Ok(Self {
            base,
            capacity,
            cursor: 0,
        })
    }

    pub(super) fn begin_write(&mut self, len: usize) -> Result<CacheWriter<'_>, DsrError> {
        if len == 0 || !len.is_multiple_of(std::mem::size_of::<u32>()) {
            return Err(DsrError::CachePolicy(format!(
                "translation cache write length must be a nonzero instruction multiple, got {len}"
            )));
        }
        let end = self.cursor.checked_add(len).ok_or_else(|| {
            DsrError::CachePolicy("translation cache cursor overflow".to_string())
        })?;
        if end > self.capacity {
            return Err(DsrError::CachePolicy(format!(
                "translation cache exhausted: requested={len} remaining={}",
                self.capacity - self.cursor
            )));
        }
        let start = self.cursor;
        unsafe { libc::pthread_jit_write_protect_np(0) };
        Ok(CacheWriter {
            cache: self,
            start,
            len,
            written: 0,
            write_enabled: true,
        })
    }

    pub(super) fn contains_host_pc(&self, pc: HostVa) -> bool {
        let start = self.base.as_ptr() as usize;
        let end = start.saturating_add(self.cursor);
        (start..end).contains(&pc.raw())
    }
}

impl Drop for TranslationCache {
    fn drop(&mut self) {
        unsafe { libc::pthread_jit_write_protect_np(1) };
        let _ = unsafe { libc::munmap(self.base.as_ptr().cast(), self.capacity) };
    }
}

pub(super) struct CacheWriter<'a> {
    cache: &'a mut TranslationCache,
    start: usize,
    len: usize,
    written: usize,
    write_enabled: bool,
}

impl CacheWriter<'_> {
    #[cfg(test)]
    pub(super) fn entry_for_test(&self) -> CacheVa {
        let ptr = unsafe { self.cache.base.as_ptr().add(self.start) };
        CacheVa::published(HostVa(ptr as usize))
    }

    pub(super) fn write_words(&mut self, words: &[u32]) -> Result<(), DsrError> {
        let byte_len = words
            .len()
            .checked_mul(std::mem::size_of::<u32>())
            .ok_or_else(|| DsrError::CachePolicy("emitted code size overflow".to_string()))?;
        if byte_len != self.len {
            return Err(DsrError::CachePolicy(format!(
                "emitted code length mismatch: reserved={} emitted={byte_len}",
                self.len
            )));
        }
        let destination = unsafe { self.cache.base.as_ptr().add(self.start).cast::<u32>() };
        unsafe { std::ptr::copy_nonoverlapping(words.as_ptr(), destination, words.len()) };
        self.written = byte_len;
        Ok(())
    }

    pub(super) fn publish(mut self) -> Result<PublishedCode, DsrError> {
        if self.written != self.len {
            return Err(DsrError::CachePolicy(format!(
                "cannot publish incomplete code: reserved={} written={}",
                self.len, self.written
            )));
        }
        let entry_ptr = unsafe { self.cache.base.as_ptr().add(self.start) };
        unsafe { super::super::carrick_native_clear_icache(entry_ptr.cast(), self.len) };
        unsafe { libc::pthread_jit_write_protect_np(1) };
        self.write_enabled = false;
        self.cache.cursor += self.len;
        Ok(PublishedCode {
            entry: CacheVa::published(HostVa(entry_ptr as usize)),
            len: self.len,
        })
    }
}

impl Drop for CacheWriter<'_> {
    fn drop(&mut self) {
        if self.write_enabled {
            unsafe { libc::pthread_jit_write_protect_np(1) };
        }
    }
}
