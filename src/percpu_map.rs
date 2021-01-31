use errno::{set_errno, Errno};
use lazy_static::lazy_static;
use libbpf_sys as bpf;
use std::{convert::TryInto, marker::PhantomData, mem::size_of, os::raw::c_void};

use crate::error::{get_errno, reset_errno, XDPError};
use crate::map_batch::*;
use crate::map_common as mc;
use crate::object::XDPLoadedObject;
use crate::result::XDPResult;
use crate::utils;
use crate::{KeyValue, MapFlags, MapType};

lazy_static! {
    pub static ref NUM_CPUS: usize = utils::num_cpus().unwrap();
}

/// Handles interacting with the underlying per-cpu eBPF map.
pub struct PerCpuMap<K, V> {
    map_fd: i32,
    _key: PhantomData<K>,
    _val: PhantomData<V>,
    pub map_type: MapType,

    /// The maximum number of entries the map supports
    pub max_entries: u32,
    value_size: usize,
}

impl<K: Default, V: ByteAligned> PerCpuMap<K, V> {
    /// Create a new map.
    pub fn create(
        map_type: MapType,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
    ) -> XDPResult<PerCpuMap<K, V>> {
        if !map_type.is_per_cpu() {
            set_errno(Errno(22));
            return Err(XDPError::new("Improper map type, use rxdp::Map::create"));
        }

        let map_fd = mc::create_map(map_type, key_size, value_size, max_entries, map_flags);

        let m = PerCpuMap {
            map_fd,
            _key: PhantomData,
            _val: PhantomData,
            map_type,
            max_entries,
            value_size: align(value_size),
        };

        mc::check_rc(map_fd, m, "Error creating new map")
    }

    /// Get access to the eBPF map `map_name`. This will fail if the requested key size
    /// doesn't match the key size defined in the ELF file.
    pub fn new(xdp: &XDPLoadedObject, map_name: &str) -> XDPResult<PerCpuMap<K, V>> {
        let (map_fd, _, mtype, max_entries) = PerCpuMap::<K, V>::validate_map(xdp, map_name)?;

        let map_type: MapType = mtype.into();
        if !map_type.is_per_cpu() {
            set_errno(Errno(22));
            return Err(XDPError::new("Improper map type, use rxdp::Map::new"));
        }

        Ok(PerCpuMap {
            map_fd,
            _key: PhantomData,
            _val: PhantomData,
            map_type,
            max_entries,
            value_size: align(size_of::<V>() as u32),
        })
    }

    /// Update an element in the underlying eBPF map.
    pub fn update(&self, key: &K, value: &V, flags: MapFlags) -> XDPResult<()> {
        let mut values: Vec<u8> = Vec::with_capacity(*NUM_CPUS);
        for _ in 0..*NUM_CPUS {
            values.extend_from_slice(value.align().as_slice());
        }

        mc::update_elem(
            self.map_fd,
            key as *const _ as *const c_void,
            values.as_mut_ptr() as *const c_void,
            flags as u64,
        )
    }

    /// Lookup an element from the underlying eBPF map.
    pub fn lookup(&self, key: &K) -> XDPResult<Vec<V>> {
        let s: usize = *NUM_CPUS * self.value_size;
        let mut value: Vec<u8> = Vec::with_capacity(s);
        value.resize_with(s, Default::default);

        let rc = mc::lookup_elem(
            self.map_fd,
            key as *const _ as *const c_void,
            value.as_mut_ptr() as *mut c_void,
        );

        let mut r = Vec::with_capacity(*NUM_CPUS);
        if rc >= 0 {
            let mut iter = value.as_mut_slice().chunks_exact_mut(self.value_size);
            while let Some(chunk) = iter.next() {
                r.push(V::from_aligned(chunk));
            }
        }

        return mc::check_rc(rc, r, "Error looking up elem");
    }

    /// Update a batch of elements in the underlying eBPF map. If the kernel supports it, this
    /// will use the `BPF_MAP_UPDATE_BATCH` syscall to update all elements in 1 call. Otherwise,
    /// it is equivalent to calling `update()` in a loop for every element.
    /// **NOTE**: PerCPUArray does not support batching, so will fall back to looping.
    pub fn update_batch(
        &self,
        keys: &mut Vec<K>,
        values: &mut Vec<V>,
        flags: MapFlags,
    ) -> XDPResult<u32> {
        let num_keys = keys.len();
        let num_vals = values.len();
        if num_keys != num_vals {
            set_errno(Errno(22));
            let err = format!(
                "Num keys must match num values. Got {} keys, {} values",
                num_keys, num_vals
            );
            return Err(XDPError::new(&err));
        }

        if self.map_type.is_array() || !*BATCHING_SUPPORTED {
            for i in 0..num_keys {
                self.update(&keys[i], &values[i], flags)?
            }

            return Ok(num_keys as u32);
        }

        let mut count: u32 = num_keys as u32;
        let opts = bpf::bpf_map_batch_opts {
            sz: 24u64,
            elem_flags: flags as u64,
            flags: 0u64,
        };

        let mut per_cpu_values: Vec<u8> = Vec::with_capacity(*NUM_CPUS * num_vals);
        for v in values {
            for _ in 0..*NUM_CPUS {
                per_cpu_values.extend_from_slice(v.align().as_slice());
            }
        }

        let rc = mc::update_batch(
            self.map_fd,
            keys.as_mut_ptr() as *mut c_void,
            per_cpu_values.as_mut_ptr() as *mut c_void,
            &mut count,
            &opts,
        );

        mc::check_rc(rc, count, "Error updating batch of elements")
    }

    /// Lookup a batch of elements from the underlying eBPF map. Returns a
    /// [`BatchResult`](crate::maps::BatchResult) that includes the next key to pass in to
    /// continue looking up elements:
    /// ```ignore
    /// let next_key = None;
    /// loop {
    ///     let r = m.lookup_batch(10u32, next_key)?;
    ///     // do something with `r.items`...
    ///
    ///     if r.next_key.is_none() {
    ///         break;
    ///     }
    ///     next_key = r.next_key;
    /// }
    /// ```
    /// **NOTE**: By design of the bpf kernel code, this may return anywhere from 0 - `batch_size`
    /// elements, particularly when the `batch_size` is small. If the number of elements returned
    /// is frequently less than the requested `batch_size`, increasing the `batch_size` will help.
    ///
    /// **NOTE**: This function will return an error if the kernel doesn't support batching or the
    ///           map type is PerCPUArray.
    pub fn lookup_batch(
        &self,
        batch_size: u32,
        next_key: Option<u32>,
    ) -> XDPResult<BatchResult<K, Vec<V>>> {
        self.lookup_batch_impl(batch_size, next_key, false)
    }

    /// Lookup and delete a batch of elements from the underlying eBPF map. Returns a
    /// [`BatchResult`](crate::maps::BatchResult) that includes the next key to pass in to
    /// continue looking up elements:
    /// ```ignore
    /// let next_key = None;
    /// loop {
    ///     let r = m.lookup_and_delete_batch(10u32, next_key)?;
    ///     // do something with `r.items`...
    ///
    ///     if r.next_key.is_none() {
    ///         break;
    ///     }
    ///     next_key = r.next_key;
    /// }
    /// ```
    /// **NOTE**: By design of the bpf kernel code, this may return anywhere from 0 - `batch_size`
    /// elements, particularly when the `batch_size` is small. If the number of elements returned
    /// is frequently less than the requested `batch_size`, increasing the `batch_size` will help.
    ///
    /// **NOTE**: This function will return an error if the kernel doesn't support batching or the
    ///           map type is PerCPUArray.
    pub fn lookup_and_delete_batch(
        &self,
        batch_size: u32,
        next_key: Option<u32>,
    ) -> XDPResult<BatchResult<K, Vec<V>>> {
        self.lookup_batch_impl(batch_size, next_key, true)
    }

    fn lookup_batch_impl(
        &self,
        batch_size: u32,
        next_key: Option<u32>,
        delete: bool,
    ) -> XDPResult<BatchResult<K, Vec<V>>> {
        // Array map types do not support deletes, do an early return to save a syscall.
        if self.map_type.is_array() && delete {
            set_errno(Errno(22));
            return Err(XDPError::new("Delete not supported on this map type"));
        }

        if !*BATCHING_SUPPORTED {
            set_errno(Errno(95));
            return Err(XDPError::new("Batching not supported"));
        }

        let mut keys: Vec<K> = Vec::with_capacity(batch_size as usize);

        let vals_size = batch_size as usize * *NUM_CPUS * self.value_size;
        let mut vals: Vec<u8> = Vec::with_capacity(vals_size);
        keys.resize_with(batch_size as usize, Default::default);
        vals.resize_with(vals_size, Default::default);

        let r = self.lookup_batch_prealloc(batch_size, next_key, &mut keys, &mut vals, delete)?;
        let mut result = Vec::with_capacity(r.num_items as usize);
        populate_batch_result(
            r.num_items,
            &mut result,
            &mut keys,
            &mut vals,
            self.value_size,
        );

        Ok(BatchResult {
            items: result,
            next_key: r.next_key,
            num_items: r.num_items,
        })
    }

    fn _items(&self) -> XDPResult<Vec<KeyValue<K, Vec<V>>>>
    where
        K: Copy,
    {
        let mut key: K = Default::default();
        let mut result = Vec::with_capacity(self.max_entries as usize);
        let mut more = {
            let first_key: *const i32 = std::ptr::null();
            self.get_next_key(first_key as *const c_void, &mut key)
                .is_ok()
        };

        while more {
            result.push(KeyValue {
                key: key,
                value: self.lookup(&key)?,
            });

            more = self
                .get_next_key(&key as *const _ as *const c_void, &mut key)
                .is_ok();
        }

        Ok(result)
    }

    #[inline]
    /// Returns all items in the map. Note that for Array type maps, this will always
    /// return `max_entries` number of items.
    pub fn items(&self) -> XDPResult<Vec<KeyValue<K, Vec<V>>>>
    where
        K: Copy,
    {
        if self.map_type.is_array() || self.max_entries < 50 || !*BATCHING_SUPPORTED {
            return self._items();
        }
        let mut keys: Vec<K> = Vec::with_capacity(BATCH_SIZE as usize);

        let vals_size = BATCH_SIZE as usize * *NUM_CPUS * self.value_size;
        let mut vals: Vec<u8> = Vec::with_capacity(vals_size);

        let mut result = Vec::with_capacity(BATCH_SIZE as usize);
        let mut next_key = None;

        loop {
            keys.resize_with(BATCH_SIZE as usize, Default::default);
            vals.resize_with(vals_size, Default::default);
            let r =
                self.lookup_batch_prealloc(BATCH_SIZE, next_key, &mut keys, &mut vals, false)?;
            populate_batch_result(
                r.num_items,
                &mut result,
                &mut keys,
                &mut vals,
                self.value_size,
            );

            if r.next_key.is_none() {
                break;
            }
            next_key = r.next_key;
        }

        Ok(result)
    }
}

fn populate_batch_result<K, V: ByteAligned>(
    n: u32,
    result: &mut Vec<KeyValue<K, Vec<V>>>,
    keys: &mut Vec<K>,
    vals: &mut Vec<u8>,
    value_size: usize,
) {
    vals.truncate(n as usize * *NUM_CPUS * value_size);
    let mut iter = vals.as_mut_slice().chunks_exact_mut(value_size).rev();

    for k in keys.drain(..n as usize).rev() {
        let mut r = Vec::with_capacity(*NUM_CPUS);
        let mut count = 0;
        while let Some(chunk) = iter.next() {
            r.push(V::from_aligned(chunk));
            count += 1;
            if count == *NUM_CPUS {
                break;
            }
        }

        result.push(KeyValue { key: k, value: r })
    }
}

fn align(v: u32) -> usize {
    (((v + 7) / 8) * 8) as usize
}

pub trait ByteAligned: Default + Copy + std::fmt::Debug {
    fn align(self) -> Vec<u8>;

    fn from_aligned(chunk: &[u8]) -> Self;
}

macro_rules! impl_num_byte_aligned {
    ($t:ty, $c:ty) => {
        impl ByteAligned for $t {
            fn align(self) -> Vec<u8> {
                (self as $c).to_le_bytes().to_vec()
            }

            fn from_aligned(chunk: &[u8]) -> Self {
                <$c>::from_le_bytes(chunk.try_into().unwrap()) as $t
            }
        }
    };
}

impl_map_common!(PerCpuMap);

impl_num_byte_aligned!(u8, u64);
impl_num_byte_aligned!(u16, u64);
impl_num_byte_aligned!(u32, u64);
impl_num_byte_aligned!(u64, u64);
impl_num_byte_aligned!(u128, u128);
impl_num_byte_aligned!(usize, u64);
impl_num_byte_aligned!(i8, i64);
impl_num_byte_aligned!(i16, i64);
impl_num_byte_aligned!(i32, i64);
impl_num_byte_aligned!(i64, i64);
impl_num_byte_aligned!(i128, i128);
impl_num_byte_aligned!(isize, i64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_align_numbers() {
        let expected = vec![100, 0, 0, 0, 0, 0, 0, 0];
        let expected_big = vec![100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(100u8.align(), expected);
        assert_eq!(100u16.align(), expected);
        assert_eq!(100u32.align(), expected);
        assert_eq!(100u64.align(), expected);
        assert_eq!(100u128.align(), expected_big);
        assert_eq!(100usize.align(), expected);

        assert_eq!(100i8.align(), expected);
        assert_eq!(100i16.align(), expected);
        assert_eq!(100i32.align(), expected);
        assert_eq!(100i64.align(), expected);
        assert_eq!(100i128.align(), expected_big);
        assert_eq!(100isize.align(), expected);
    }

    #[test]
    fn test_byte_from_aligned_numbers() {
        let chunk = vec![100, 0, 0, 0, 0, 0, 0, 0];
        let chunk_big = vec![100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(100u8, u8::from_aligned(&chunk));
        assert_eq!(100u16, u16::from_aligned(&chunk));
        assert_eq!(100u32, u32::from_aligned(&chunk));
        assert_eq!(100u64, u64::from_aligned(&chunk));
        assert_eq!(100u128, u128::from_aligned(&chunk_big));
        assert_eq!(100usize, usize::from_aligned(&chunk));

        assert_eq!(100u8, u8::from_aligned(&chunk));
        assert_eq!(100u16, u16::from_aligned(&chunk));
        assert_eq!(100u32, u32::from_aligned(&chunk));
        assert_eq!(100u64, u64::from_aligned(&chunk));
        assert_eq!(100i128, i128::from_aligned(&chunk_big));
        assert_eq!(100usize, usize::from_aligned(&chunk));
    }
}
