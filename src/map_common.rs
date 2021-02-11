use errno::{set_errno, Errno};
use libbpf_sys as bpf;
use std::{mem::size_of, os::raw::c_void};

use crate::error::{get_errno, reset_errno};
use crate::map_batch::*;
use crate::utils;
use crate::{BatchResult, MapFlags, MapType, XDPError, XDPLoadedObject, XDPResult};

/// Holds key/value pair when getting all items from a map.
#[derive(Debug)]
pub struct KeyValue<K, V> {
    pub key: K,
    pub value: V,
}

#[derive(PartialEq, Eq, Debug)]
/// Return value from eBPF maps.
pub enum MapValue<V> {
    /// Result from cpu-shared maps.
    Single(V),

    /// Result from per-cpu maps.
    Multi(Vec<V>),
}

impl<V> MapValue<V> {
    /// Convert the map value into a `Vec<V>`:
    /// ```
    /// use rxdp::MapValue;
    /// assert_eq!(MapValue::Multi(vec![1u32]).into_vec(), vec![1u32]);
    /// assert_eq!(MapValue::Single(1u32).into_vec(), vec![1u32]);
    /// ```
    pub fn into_vec(self) -> Vec<V> {
        match self {
            MapValue::Multi(r) => r,
            MapValue::Single(r) => vec![r],
        }
    }

    /// Convert the map value into a `V`. For the `Multi` variant, this will take the first
    /// element of the `Vec`:
    /// ```
    /// use rxdp::MapValue;
    /// assert_eq!(MapValue::Multi(vec![1u32, 2u32]).into_single(), 1u32);
    /// assert_eq!(MapValue::Single(1u32).into_single(), 1u32);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if len of `Vec` in Multi is 0.
    pub fn into_single(self) -> V {
        match self {
            MapValue::Multi(mut r) => r.swap_remove(0),
            MapValue::Single(r) => r,
        }
    }
}

/// This trait exposes the functionality of update/lookup/delete of underlying eBPF maps.
pub trait MapLike<K, V: Default> {
    #[doc(hidden)]
    fn get_next_key(&self, prev_key: *const c_void, key: &mut K) -> XDPResult<()> {
        let rc = unsafe {
            bpf::bpf_map_get_next_key(self.map_fd(), prev_key, key as *mut _ as *mut c_void)
        };

        crate::map_common::check_rc(rc, (), "Error getting next key")
    }

    #[doc(hidden)]
    fn update_batching_not_supported(&self) -> bool;

    #[doc(hidden)]
    fn update_batch_impl(
        &self,
        keys: &mut Vec<K>,
        values: &mut Vec<V>,
        opts: &bpf::bpf_map_batch_opts,
    ) -> (i32, u32) {
        let mut count: u32 = keys.len() as u32;
        let rc = crate::map_common::update_batch(
            self.map_fd(),
            keys.as_mut_ptr() as *mut c_void,
            values.as_mut_ptr() as *mut c_void,
            &mut count,
            &opts,
        );

        (rc, count)
    }

    #[doc(hidden)]
    fn lookup_batch_impl(
        &self,
        batch_size: u32,
        next_key: Option<u32>,
        delete: bool,
    ) -> XDPResult<BatchResult<K, MapValue<V>>>;

    #[doc(hidden)]
    fn _items(&self) -> XDPResult<Vec<KeyValue<K, MapValue<V>>>>;

    /// File descriptor for this map.
    fn map_fd(&self) -> i32;

    fn map_type(&self) -> MapType;

    /// The maximum number of entries the map supports
    fn max_entries(&self) -> u32;

    /// Lookup an element from the underlying eBPF map.
    fn lookup(&self, key: &K) -> XDPResult<MapValue<V>> {
        let mut value: V = Default::default();
        let rc = crate::map_common::lookup_elem(
            self.map_fd(),
            key as *const _ as *const c_void,
            &mut value as *mut _ as *mut c_void,
        );

        crate::map_common::check_rc(rc, MapValue::Single(value), "Error looking up elem")
    }

    /// Update an element in the underlying eBPF map.
    fn update(&self, key: &K, value: &V, flags: MapFlags) -> XDPResult<()> {
        crate::map_common::update_elem(
            self.map_fd(),
            key as *const _ as *const c_void,
            value as *const _ as *const c_void,
            flags as u64,
        )
    }

    /// Delete an element from the underlying eBPF map.
    fn delete(&self, key: &K) -> XDPResult<()> {
        // Array map types do not support deletes, do an early return to save a syscall.
        if self.map_type().is_array() {
            set_errno(Errno(22));
            fail!("Delete not supported on this map type");
        }

        let rc =
            unsafe { bpf::bpf_map_delete_elem(self.map_fd(), key as *const _ as *const c_void) };

        crate::map_common::check_rc(rc, (), "Error deleting elem")
    }

    /// Update a batch of elements in the underlying eBPF map. If the kernel supports it, this
    /// will use the `BPF_MAP_UPDATE_BATCH` syscall to update all elements in 1 call. Otherwise,
    /// it is equivalent to calling `update()` in a loop for every element.
    fn update_batch(
        &self,
        keys: &mut Vec<K>,
        values: &mut Vec<V>,
        flags: MapFlags,
    ) -> XDPResult<u32> {
        let num_keys = keys.len();
        let num_vals = values.len();
        if num_keys != num_vals {
            set_errno(Errno(22));
            fail!(
                "Num keys must match num values. Got {} keys, {} values",
                num_keys,
                num_vals
            );
        }

        if self.update_batching_not_supported() {
            for i in 0..num_keys {
                self.update(&keys[i], &values[i], flags)?
            }

            return Ok(num_keys as u32);
        }

        let opts = bpf::bpf_map_batch_opts {
            sz: 24u64,
            elem_flags: flags as u64,
            flags: 0u64,
        };
        let (rc, count) = self.update_batch_impl(keys, values, &opts);

        crate::map_common::check_rc(rc, count, "Error updating batch of elements")
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
    /// **NOTE**: This function will return an error if the kernel doesn't support batching or the
    ///           map type is PerCPUArray.
    fn lookup_batch(
        &self,
        batch_size: u32,
        next_key: Option<u32>,
    ) -> XDPResult<BatchResult<K, MapValue<V>>> {
        if !is_batching_supported() {
            set_errno(Errno(95));
            fail!("Batching not supported");
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
    /// **NOTE**: This function will return an error if the kernel doesn't support batching or the
    ///           map type is PerCPUArray.
    fn lookup_and_delete_batch(
        &self,
        batch_size: u32,
        next_key: Option<u32>,
    ) -> XDPResult<BatchResult<K, MapValue<V>>> {
        if !is_batching_supported() {
            set_errno(Errno(95));
            fail!("Batching not supported");
        }

        // Array map types do not support deletes, do an early return to save a syscall.
        if self.map_type().is_array() {
            set_errno(Errno(22));
            fail!("Delete not supported on this map type");
        }

        self.lookup_batch_impl(batch_size, next_key, true)
    }

    /// Returns all items in the map. Note that for Array type maps, this will always
    /// return `max_entries` number of items.
    fn items(&self) -> XDPResult<Vec<KeyValue<K, MapValue<V>>>>;
}

pub(crate) fn check_rc<T>(rc: i32, ret: T, err_msg: &str) -> XDPResult<T> {
    if rc < 0 {
        fail!(err_msg);
    }

    Ok(ret)
}

pub(crate) fn create_map(
    map_type: MapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
) -> i32 {
    unsafe {
        bpf::bpf_create_map(
            map_type as u32,
            key_size as i32,
            value_size as i32,
            max_entries as i32,
            map_flags,
        )
    }
}

pub(crate) fn update_elem(
    fd: i32,
    key: *const c_void,
    val: *const c_void,
    flags: u64,
) -> XDPResult<()> {
    let rc = unsafe { bpf::bpf_map_update_elem(fd, key, val, flags) };
    check_rc(rc, (), "Error updating elem")
}

pub(crate) fn lookup_elem(fd: i32, key: *const c_void, val: *mut c_void) -> i32 {
    unsafe { bpf::bpf_map_lookup_elem(fd, key, val) }
}

pub(crate) fn update_batch(
    fd: i32,
    key: *mut c_void,
    val: *mut c_void,
    count: &mut u32,
    opts: &bpf::bpf_map_batch_opts,
) -> i32 {
    unsafe { bpf::bpf_map_update_batch(fd, key, val, count, opts) }
}

pub(crate) fn lookup_batch_prealloc<K, T>(
    map_fd: i32,
    batch_size: u32,
    next_key: Option<u32>,
    keys: &mut Vec<K>,
    vals: &mut Vec<T>,
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
            map_fd,
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

pub(crate) fn validate_map<K>(
    xdp: &XDPLoadedObject,
    map_name: &str,
) -> XDPResult<(i32, u32, u32, u32)> {
    let name = utils::str_to_cstring(map_name)?;
    let (map_fd, map, map_def) = unsafe {
        let map_fd = bpf::bpf_object__find_map_fd_by_name(xdp.object, name.as_ptr());
        let map = bpf::bpf_object__find_map_by_name(xdp.object, name.as_ptr());

        let map_def = bpf::bpf_map__def(map);
        (map_fd, map, map_def)
    };

    if map_fd < 0 || map.is_null() || map_def.is_null() {
        fail!("Unable to find map with name '{}'", map_name);
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

    let req_key_size = size_of::<K>() as u32;
    if req_key_size != ksize {
        fail!(
            "Incorrect key size, XDP map has size: {}, requested key size is {}.",
            ksize,
            req_key_size,
        );
    }

    Ok((map_fd, vsize, mtype, max_entries))
}
