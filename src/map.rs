use errno::{set_errno, Errno};
use libbpf_sys as bpf;
use std::{marker::PhantomData, mem::size_of, os::raw::c_void};

use crate::error::{get_errno, reset_errno, XDPError};
use crate::map_batch::*;
use crate::map_common as mc;
use crate::object::XDPLoadedObject;
use crate::result::XDPResult;
use crate::utils;
use crate::{KeyValue, MapFlags, MapType};

/// Handles interacting with the underlying eBPF map.
pub struct Map<K, V> {
    map_fd: i32,
    _key: PhantomData<K>,
    _val: PhantomData<V>,
    pub map_type: MapType,

    /// The maximum number of entries the map supports
    pub max_entries: u32,
}

impl<K: Default, V: Default> Map<K, V> {
    /// Create a new map.
    pub fn create(
        map_type: MapType,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
    ) -> XDPResult<Map<K, V>> {
        Map::<K, V>::_create(map_type, key_size, value_size, max_entries, map_flags, true)
    }

    pub(crate) fn _create(
        map_type: MapType,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
        check_batch: bool,
    ) -> XDPResult<Map<K, V>> {
        let map_fd = mc::create_map(map_type, key_size, value_size, max_entries, map_flags);

        if check_batch {
            let _ = is_batching_supported();
        }

        let m = Map {
            map_fd,
            _key: PhantomData,
            _val: PhantomData,
            map_type,
            max_entries,
        };

        mc::check_rc(map_fd, m, "Error creating new map")
    }

    /// Get access to the eBPF map `map_name`. This will fail if the requested key/value sizes
    /// don't match the key/value sizes defined in the ELF file.
    pub fn new(xdp: &XDPLoadedObject, map_name: &str) -> XDPResult<Map<K, V>> {
        let (map_fd, vsize, mtype, max_entries) = Map::<K, V>::validate_map(xdp, map_name)?;

        let map_type: MapType = mtype.into();
        if map_type.is_per_cpu() {
            set_errno(Errno(22));
            return Err(XDPError::new("Improper map type, use rxdp::PerCPUMap::new"));
        }

        let req_val_size = size_of::<V>() as u32;
        if req_val_size != vsize {
            let error_msg = format!(
                "Incorrect value size, XDP map has size: {}, requested value size is {}.",
                vsize, req_val_size,
            );
            return Err(XDPError::new(&error_msg));
        }

        Ok(Map {
            map_fd,
            _key: PhantomData,
            _val: PhantomData,
            map_type,
            max_entries,
        })
    }

    /// Update an element in the underlying eBPF map.
    pub fn update(&self, key: &K, value: &V, flags: MapFlags) -> XDPResult<()> {
        mc::update_elem(
            self.map_fd,
            key as *const _ as *const c_void,
            value as *const _ as *const c_void,
            flags as u64,
        )
    }

    /// Update a batch of elements in the underlying eBPF map. If the kernel supports it, this
    /// will use the `BPF_MAP_UPDATE_BATCH` syscall to update all elements in 1 call. Otherwise,
    /// it is equivalent to calling `update()` in a loop for every element.
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

        if !is_batching_supported() {
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
        let rc = mc::update_batch(
            self.map_fd,
            keys.as_mut_ptr() as *mut c_void,
            values.as_mut_ptr() as *mut c_void,
            &mut count,
            &opts,
        );

        mc::check_rc(rc, count, "Error updating batch of elements")
    }

    /// Lookup an element from the underlying eBPF map.
    pub fn lookup(&self, key: &K) -> XDPResult<V> {
        let mut value: V = Default::default();
        let rc = mc::lookup_elem(
            self.map_fd,
            key as *const _ as *const c_void,
            &mut value as *mut _ as *mut c_void,
        );

        mc::check_rc(rc, value, "Error looking up elem")
    }

    /// Lookup a batch of elements from the underlying eBPF map. Returns a
    /// [`BatchResult`](crate::BatchResult) that includes the next key to pass in to
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
    /// **NOTE**: This function will return an error if the kernel doesn't support batching
    pub fn lookup_batch(
        &self,
        batch_size: u32,
        next_key: Option<u32>,
    ) -> XDPResult<BatchResult<K, V>> {
        if !is_batching_supported() {
            set_errno(Errno(95));
            return Err(XDPError::new("Batching not supported"));
        }

        self.lookup_batch_impl(batch_size, next_key, false)
    }

    /// Lookup and delete a batch of elements from the underlying eBPF map. Returns a
    /// [`BatchResult`](crate::BatchResult) that includes the next key to pass in to
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
    /// **NOTE**: This function will return an error if the kernel doesn't support batching
    pub fn lookup_and_delete_batch(
        &self,
        batch_size: u32,
        next_key: Option<u32>,
    ) -> XDPResult<BatchResult<K, V>> {
        // Array map types do not support deletes, do an early return to save a syscall.
        if self.map_type.is_array() {
            set_errno(Errno(22));
            return Err(XDPError::new("Delete not supported on this map type"));
        }

        if !is_batching_supported() {
            set_errno(Errno(95));
            return Err(XDPError::new("Batching not supported"));
        }

        self.lookup_batch_impl(batch_size, next_key, true)
    }

    pub(crate) fn lookup_batch_impl(
        &self,
        batch_size: u32,
        next_key: Option<u32>,
        delete: bool,
    ) -> XDPResult<BatchResult<K, V>> {
        let mut keys: Vec<K> = Vec::with_capacity(batch_size as usize);
        let mut vals: Vec<V> = Vec::with_capacity(batch_size as usize);
        keys.resize_with(batch_size as usize, Default::default);
        vals.resize_with(batch_size as usize, Default::default);

        let r = self.lookup_batch_prealloc(batch_size, next_key, &mut keys, &mut vals, delete)?;
        let mut result = Vec::with_capacity(r.num_items as usize);
        populate_batch_result(r.num_items, &mut result, &mut keys, &mut vals);

        Ok(BatchResult {
            items: result,
            next_key: r.next_key,
            num_items: r.num_items,
        })
    }

    fn _items(&self) -> XDPResult<Vec<KeyValue<K, V>>>
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
            // Handle special maps. DEV_MAP holds references to network interfaces, which can
            // be deleted, causing the lookup for that key to fail. However, there could be more
            // values further in the map.
            let maybe_val = self.lookup(&key);
            if self.map_type == MapType::DevMap && maybe_val.is_err() {
                more = self
                    .get_next_key(&key as *const _ as *const c_void, &mut key)
                    .is_ok();
                continue;
            }

            result.push(KeyValue {
                key: key,
                value: maybe_val?,
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
    pub fn items(&self) -> XDPResult<Vec<KeyValue<K, V>>>
    where
        K: Copy,
    {
        if self.map_type == MapType::DevMap || self.max_entries < 50 || !is_batching_supported() {
            return self._items();
        }
        let mut keys: Vec<K> = Vec::with_capacity(BATCH_SIZE as usize);
        let mut vals: Vec<V> = Vec::with_capacity(BATCH_SIZE as usize);

        let mut result = Vec::with_capacity(BATCH_SIZE as usize);
        let mut next_key = None;

        loop {
            keys.resize_with(BATCH_SIZE as usize, Default::default);
            vals.resize_with(BATCH_SIZE as usize, Default::default);
            let r =
                self.lookup_batch_prealloc(BATCH_SIZE, next_key, &mut keys, &mut vals, false)?;
            populate_batch_result(r.num_items, &mut result, &mut keys, &mut vals);

            if r.next_key.is_none() {
                break;
            }
            next_key = r.next_key;
        }

        Ok(result)
    }
}

fn populate_batch_result<K, V>(
    n: u32,
    result: &mut Vec<KeyValue<K, V>>,
    keys: &mut Vec<K>,
    vals: &mut Vec<V>,
) {
    vals.truncate(n as usize);
    for k in keys.drain(..n as usize).rev() {
        result.push(KeyValue {
            key: k,
            value: vals.pop().unwrap(),
        })
    }
}

impl_map_common!(Map);
