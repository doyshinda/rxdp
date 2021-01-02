use errno::{set_errno, Errno};
use libbpf_sys as bpf;
use std::{marker::PhantomData, mem::size_of, os::raw::c_void};

use crate::error::{get_errno, reset_errno, XDPError};
use crate::map_flags::MapFlags;
use crate::map_types::MapType;
use crate::object::XDPLoadedObject;
use crate::result::XDPResult;
use crate::utils;

const BATCH_SUPPORTED: &'static str = "RXDP_BATCH_SUPPORTED";
const BATCH_SIZE: u32 = 100;
const BATCH_OPTS: bpf::bpf_map_batch_opts = bpf::bpf_map_batch_opts {
    sz: 24u64,
    elem_flags: 0u64,
    flags: 0u64,
};

/// Holds key/value pair when getting all items from a map.
#[derive(Debug)]
pub struct KeyValue<K, V> {
    pub key: K,
    pub value: V,
}

/// The result of a batch operation.
pub struct BatchResult<K, V> {
    pub items: Vec<KeyValue<K, V>>,
    pub next_key: Option<u32>,
    pub num_items: u32,
}

struct BatchResultInternal {
    next_key: Option<u32>,
    num_items: u32,
}

/// Handles interacting with the underlying eBPF map.
pub struct Map<K, V> {
    map_fd: i32,
    _key: PhantomData<K>,
    _val: PhantomData<V>,
    pub map_type: MapType,

    /// The maximum number of entries the map supports
    pub max_entries: u32,
    batching_support: bool,
}

impl<K: Default, V: Default> Map<K, V> {
    /// True if the kernel supports batching calls
    pub fn batching_supported(&self) -> bool {
        self.batching_support
    }

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
        let map_fd = unsafe {
            bpf::bpf_create_map(
                map_type as u32,
                key_size as i32,
                value_size as i32,
                max_entries as i32,
                map_flags,
            )
        };

        let mut batching_support = false;
        if check_batch {
            batching_support = batching_supported();
        }

        let m = Map {
            map_fd,
            _key: PhantomData,
            _val: PhantomData,
            map_type,
            max_entries,
            batching_support,
        };

        check_rc(map_fd, m, "Error creating new map")
    }

    /// Load `map_name`. This will fail if the requested key/value sizes
    /// don't match the key/value sizes defined in the ELF file.
    pub fn new(xdp: &XDPLoadedObject, map_name: &str) -> XDPResult<Map<K, V>> {
        let name = utils::str_to_cstring(map_name)?;
        let map_fd = unsafe { bpf::bpf_object__find_map_fd_by_name(xdp.object, name.as_ptr()) };

        Map::new_map_from_fd(xdp, map_fd, map_name)
    }

    fn new_map_from_fd(xdp: &XDPLoadedObject, map_fd: i32, map_name: &str) -> XDPResult<Map<K, V>> {
        let name = utils::str_to_cstring(map_name)?;
        let (map, map_def) = unsafe {
            let map = bpf::bpf_object__find_map_by_name(xdp.object, name.as_ptr());

            let map_def = bpf::bpf_map__def(map);
            (map, map_def)
        };

        if map_fd < 0 || map.is_null() || map_def.is_null() {
            let error_msg = format!("Unable to find map with name '{}'", map_name);
            return Err(XDPError::new(&error_msg));
        }

        // Sanity check key & value sizes.
        let (ksize, vsize, mtype, max_entries) = unsafe {
            (
                (*map_def).key_size,
                (*map_def).value_size,
                (*map_def).type_,
                (*map_def).max_entries,
            )
        };
        let (req_key_size, req_val_size) = (size_of::<K>() as u32, size_of::<V>() as u32);
        if req_key_size != ksize {
            let error_msg = format!(
                "Incorrect key size, XDP map has size: {}, requested key size is {}.",
                ksize, req_key_size,
            );
            return Err(XDPError::new(&error_msg));
        }

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
            map_type: mtype.into(),
            max_entries,
            batching_support: batching_supported(),
        })
    }

    /// Update an element in the underlying eBPF map.
    pub fn update(&self, key: &K, value: &V, flags: MapFlags) -> XDPResult<()> {
        update(self.map_fd, key, value, flags as u64)
    }

    /// Update a batch of elements in the underlying eBPF map. If the kernel supports it, this
    /// will use the `BPF_MAP_UPDATE_BATCH` syscall to update all elements in 1 call. Otherwise,
    /// it is equavalent to calling `update()` in a loop for every element.
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

        let flags = flags as u64;

        if !self.batching_support {
            for i in 0..num_keys {
                update(self.map_fd, &keys[i], &values[i], flags)?
            }

            return Ok(num_keys as u32);
        }

        let mut count: u32 = num_keys as u32;
        let opts = bpf::bpf_map_batch_opts {
            sz: 24u64,
            elem_flags: flags,
            flags: 0u64,
        };
        let rc = unsafe {
            bpf::bpf_map_update_batch(
                self.map_fd,
                keys.as_mut_ptr() as *mut c_void,
                values.as_mut_ptr() as *mut c_void,
                &mut count,
                &opts,
            )
        };

        check_rc(rc, count, "Error updating batch of elements")
    }

    /// Delete an element from the underlying eBPF map.
    pub fn delete(&self, key: &K) -> XDPResult<()> {
        // Array map types do not support deletes, do an early return to save a syscall.
        if is_array(&self.map_type) {
            set_errno(Errno(22));
            return Err(XDPError::new("Delete not supported on this map type"));
        }

        let rc = unsafe { bpf::bpf_map_delete_elem(self.map_fd, key as *const _ as *const c_void) };

        check_rc(rc, (), "Error deleting elem")
    }

    /// Lookup an element from the underlying eBPF map.
    pub fn lookup(&self, key: &K) -> XDPResult<V> {
        let mut value: V = Default::default();
        let rc = unsafe {
            bpf::bpf_map_lookup_elem(
                self.map_fd,
                key as *const _ as *const c_void,
                &mut value as *mut _ as *mut c_void,
            )
        };

        check_rc(rc, value, "Error looking up elem")
    }

    /// Lookup a batch of elements from the underlying eBPF map. Returns a
    /// [`BatchResult`](crate::maps::BatchResult) that includes the next key to pass in to
    /// continue looking up elements:
    /// ```ignore
    /// let next_key = None;
    /// loop {
    ///     let r = self.lookup_batch(10u32, next_key)?;
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
        if !self.batching_support {
            set_errno(Errno(95));
            return Err(XDPError::new("Batching not supported"));
        }
        self.lookup_batch_impl(batch_size, next_key, false)
    }

    /// Lookup and delete a batch of elements from the underlying eBPF map. Returns a
    /// [`BatchResult`](crate::maps::BatchResult) that includes the next key to pass in to
    /// continue looking up elements:
    /// ```ignore
    /// let next_key = None;
    /// loop {
    ///     let r = self.lookup_and_delete_batch(10u32, next_key)?;
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
        if is_array(&self.map_type) {
            set_errno(Errno(22));
            return Err(XDPError::new("Delete not supported on this map type"));
        }

        if !self.batching_support {
            set_errno(Errno(95));
            return Err(XDPError::new("Batching not supported"));
        }

        self.lookup_batch_impl(batch_size, next_key, true)
    }

    fn lookup_batch_impl(
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

    fn lookup_batch_prealloc(
        &self,
        batch_size: u32,
        next_key: Option<u32>,
        keys: &mut Vec<K>,
        vals: &mut Vec<V>,
        delete: bool,
    ) -> XDPResult<BatchResultInternal> {
        let mut count = batch_size;
        let mut nkey = 0u32;

        reset_errno();
        let bpf_func = if delete {
            bpf::bpf_map_lookup_and_delete_batch
        } else {
            bpf::bpf_map_lookup_batch
        };

        let mut lookup = |fkey: *mut c_void| unsafe {
            bpf_func(
                self.map_fd,
                fkey,
                &mut nkey as *mut _ as *mut c_void,
                keys.as_mut_ptr() as *mut c_void,
                vals.as_mut_ptr() as *mut c_void,
                &mut count,
                &BATCH_OPTS,
            )
        };

        let mut rc = match next_key {
            Some(mut k) => lookup(&mut k as *mut _ as *mut c_void),
            None => lookup(std::ptr::null_mut() as *mut c_void),
        };

        let e = get_errno();
        if rc < 0 && (e == 28 || e == 2) {
            rc = 0;
        }

        let next_key = match e {
            2 => None,
            _ => Some(nkey),
        };

        let ret = BatchResultInternal {
            next_key: next_key,
            num_items: count,
        };

        check_rc(rc, ret, "Error looking up batch of elements")
    }

    fn get_next_key(&self, prev_key: *const c_void, key: &mut K) -> XDPResult<()> {
        let rc = unsafe {
            bpf::bpf_map_get_next_key(self.map_fd, prev_key, key as *mut _ as *mut c_void)
        };

        check_rc(rc, (), "Error getting next key")
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
        if self.map_type == MapType::DevMap || self.max_entries < 50 || !self.batching_support {
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

fn update<K, V>(map_fd: i32, key: &K, value: &V, flags: u64) -> XDPResult<()> {
    let rc = unsafe {
        bpf::bpf_map_update_elem(
            map_fd,
            key as *const _ as *const c_void,
            value as *const _ as *const c_void,
            flags,
        )
    };

    check_rc(rc, (), "Error updating elem")
}

fn check_rc<T>(rc: i32, ret: T, err_msg: &str) -> XDPResult<T> {
    if rc < 0 {
        Err(XDPError::new(err_msg))
    } else {
        Ok(ret)
    }
}

fn is_array(mt: &MapType) -> bool {
    match *mt {
        MapType::Array
        | MapType::PerCPUArray
        | MapType::ArrayOfMaps
        | MapType::ProgArray
        | MapType::PerfEventArray => true,
        _ => false,
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

fn batching_supported() -> bool {
    if let Ok(v) = std::env::var(BATCH_SUPPORTED) {
        match v.as_str() {
            "0" => return false,
            _ => return true,
        }
    }

    match Map::<u32, u32>::_create(MapType::Hash, 4, 4, 10, 0, false).and_then(|m| {
        m.update(&0u32, &0u32, MapFlags::BpfAny)
            .and_then(|_| m.lookup_batch_impl(10, None, false))
    }) {
        Err(_) => {
            std::env::set_var(BATCH_SUPPORTED, "0");
            false
        }
        Ok(_) => {
            std::env::set_var(BATCH_SUPPORTED, "1");
            true
        }
    }
}
