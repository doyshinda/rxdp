use errno::{set_errno, Errno};
use libbpf_sys as bpf;
use std::{marker::PhantomData, mem::size_of, os::raw::c_void};

use crate::error::{get_errno, reset_errno, XDPError};
use crate::map_types::MapType;
use crate::object::XDPLoadedObject;
use crate::result::XDPResult;
use crate::utils;

const BATCH_SIZE: u32 = 100;
const BATCH_OPTS: bpf::bpf_map_batch_opts = bpf::bpf_map_batch_opts {
    sz: 24u64,
    elem_flags: 0u64,
    flags: 0u64,
};

/// Flags that control map `update` behaviour.
#[repr(u32)]
pub enum MapFlags {
    /// Create a new element or update an existing element.
    BpfAny = bpf::BPF_ANY,

    /// Create a new element only if it did not exist.
    BpfNoExist = bpf::BPF_NOEXIST,

    /// Update an existing element.
    BpfExist = bpf::BPF_EXIST,
}

impl From<MapFlags> for u64 {
    fn from(mp: MapFlags) -> u64 {
        match mp {
            MapFlags::BpfAny => 0u64,
            MapFlags::BpfNoExist => 1u64,
            MapFlags::BpfExist => 2u64,
        }
    }
}

/// Struct to hold key/value pair when getting all items from a map.
#[derive(Debug)]
pub struct KeyValue<K, V> {
    pub key: K,
    pub value: V,
}

// Struct to hold the result of a batch operation.
pub struct BatchResult<K, V> {
    pub items: Vec<KeyValue<K, V>>,
    pub next_key: Option<u32>,
    pub num_items: u32,
}

struct BatchResultInternal {
    next_key: Option<u32>,
    num_items: u32,
}

/// Struct that handles interacting with the underlying eBPF map.
pub struct Map<K, V> {
    map_fd: i32,
    _key: PhantomData<K>,
    _val: PhantomData<V>,
    pub map_type: MapType,

    /// The maximum number of entries the map supports
    pub max_entries: u32,
}

impl<K: Default, V: Default> Map<K, V> {
    /// Create and load `map_name`. This will fail if the requested key/value sizes
    /// doesn't match the key/value sizes defined in the underlying eBPF map.
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
        })
    }

    #[inline]
    /// Update an element in the underlying eBPF map.
    pub fn update(&mut self, key: &K, value: &V, flags: MapFlags) -> XDPResult<()> {
        let rc = unsafe {
            bpf::bpf_map_update_elem(
                self.map_fd,
                key as *const _ as *const c_void,
                value as *const _ as *const c_void,
                flags.into(),
            )
        };

        check_rc(rc, (), "Error updating elem")
    }

    #[inline]
    /// Update a batch of elements in the underlying eBPF map.
    pub fn update_batch(
        &mut self,
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

        let mut count: u32 = num_keys as u32;
        let opts = bpf::bpf_map_batch_opts {
            sz: 24u64,
            elem_flags: flags.into(),
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

    #[inline]
    /// Delete an element from the underlying eBPF map.
    pub fn delete(&mut self, key: &K) -> XDPResult<()> {
        // Array map types do not support deletes, do an early return to save a syscall.
        if is_array(&self.map_type) {
            set_errno(Errno(22));
            return Err(XDPError::new("Delete not supported on this map type"));
        }

        let rc = unsafe { bpf::bpf_map_delete_elem(self.map_fd, key as *const _ as *const c_void) };

        check_rc(rc, (), "Error deleting elem")
    }

    #[inline]
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

    #[inline]
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
    pub fn lookup_batch(
        &self,
        batch_size: u32,
        next_key: Option<u32>,
    ) -> XDPResult<BatchResult<K, V>> {
        let mut keys: Vec<K> = Vec::with_capacity(batch_size as usize);
        let mut vals: Vec<V> = Vec::with_capacity(batch_size as usize);
        keys.resize_with(batch_size as usize, Default::default);
        vals.resize_with(batch_size as usize, Default::default);

        let r = self.lookup_batch_prealloc(batch_size, next_key, &mut keys, &mut vals, false)?;
        let mut result = Vec::with_capacity(r.num_items as usize);
        vals.truncate(r.num_items as usize);
        for k in keys.drain(..r.num_items as usize).rev() {
            result.push(KeyValue {
                key: k,
                value: vals.pop().unwrap(),
            })
        }

        Ok(BatchResult {
            items: result,
            next_key: r.next_key,
            num_items: r.num_items,
        })
    }

    #[inline]
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

        let mut keys: Vec<K> = Vec::with_capacity(batch_size as usize);
        let mut vals: Vec<V> = Vec::with_capacity(batch_size as usize);
        keys.resize_with(batch_size as usize, Default::default);
        vals.resize_with(batch_size as usize, Default::default);

        let r = self.lookup_batch_prealloc(batch_size, next_key, &mut keys, &mut vals, true)?;
        let mut result = Vec::with_capacity(r.num_items as usize);
        vals.truncate(r.num_items as usize);
        for k in keys.drain(..r.num_items as usize).rev() {
            result.push(KeyValue {
                key: k,
                value: vals.pop().unwrap(),
            })
        }

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

    /// Can be used for partial iteration through a map (as opposed to `items`, which
    /// will return all items in the map).
    pub fn get_next_key<T>(&self, prev_key: &T, key: &mut K) -> XDPResult<()> {
        let rc = unsafe {
            bpf::bpf_map_get_next_key(
                self.map_fd,
                prev_key as *const _ as *const c_void,
                key as *mut _ as *mut c_void,
            )
        };

        check_rc(rc, (), "Error getting next key")
    }

    fn _items(&self) -> XDPResult<Vec<KeyValue<K, V>>>
    where
        K: Copy,
    {
        let mut prev_key: K = Default::default();
        let mut key: K = Default::default();

        let mut result = Vec::with_capacity(self.max_entries as usize);

        let mut c = 0;
        if is_array(&self.map_type) {
            // Bit of a hack here. `bpf_map_get_next_key` converts the pointer to the key to
            // a `u64`, so the first "key" returned in actually index 1, and we never lookup
            // the value from index 0:
            //
            // int bpf_map_get_next_key(int fd, const void *key, void *next_key)
            // {
            //     union bpf_attr attr;
            //
            //     memset(&attr, 0, sizeof(attr));
            //     attr.map_fd = fd;
            //     attr.key = ptr_to_u64(key);
            //     attr.next_key = ptr_to_u64(next_key);
            //
            //     return sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
            // }
            //
            // I'm assuming that someone isn't doing something silly like implementing `Default`
            // with a non-zero value for a `u32`/`i32` and that therefore `prev_key` will be 0.
            result.push(KeyValue {
                key: prev_key,
                value: self.lookup(&prev_key)?,
            });
            c = 1;
        }

        loop {
            let nxt = if c == 0 {
                let first_key: *const i32 = std::ptr::null();
                self.get_next_key(&first_key, &mut key)
            } else {
                self.get_next_key(&prev_key, &mut key)
            };

            if nxt.is_err() {
                break;
            }

            // Handle special maps. `get_next_key` didn't return an error, but when looking
            // up the first element, we encountered an error. This is indicative of a map that
            // had map_flags=BPF_F_NO_PREALLOC OR a DEV_MAP.
            let maybe_val = self.lookup(&key);
            if c == 0 && maybe_val.is_err() {
                return Ok(result);
            }

            result.push(KeyValue {
                key: key,
                value: maybe_val?,
            });
            prev_key = key;
            c += 1;
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
        if self.map_type == MapType::DevMap || self.max_entries < 50 {
            return self._items();
        }
        let mut keys: Vec<K> = Vec::with_capacity(BATCH_SIZE as usize);
        let mut vals: Vec<V> = Vec::with_capacity(BATCH_SIZE as usize);

        let mut result = Vec::with_capacity(1000 as usize);
        let mut next_key = None;

        loop {
            keys.resize_with(BATCH_SIZE as usize, Default::default);
            vals.resize_with(BATCH_SIZE as usize, Default::default);
            let r =
                self.lookup_batch_prealloc(BATCH_SIZE, next_key, &mut keys, &mut vals, false)?;
            vals.truncate(r.num_items as usize);
            for k in keys.drain(..r.num_items as usize).rev() {
                result.push(KeyValue {
                    key: k,
                    value: vals.pop().unwrap(),
                })
            }

            if r.next_key.is_none() {
                break;
            }
            next_key = r.next_key;
        }

        Ok(result)
    }
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
