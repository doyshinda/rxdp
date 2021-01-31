#![macro_use]

use crate::{MapType, XDPError, XDPResult};
use libbpf_sys as bpf;
use std::os::raw::c_void;

/// Holds key/value pair when getting all items from a map.
#[derive(Debug)]
pub struct KeyValue<K, V> {
    pub key: K,
    pub value: V,
}

// Macro to implement shared methods between Map and PerCpuMap
macro_rules! impl_map_common {
    ($struct_name:ident) => {
        impl<K, V> $struct_name<K, V> {
            fn validate_map(
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

                let req_key_size = size_of::<K>() as u32;
                if req_key_size != ksize {
                    let error_msg = format!(
                        "Incorrect key size, XDP map has size: {}, requested key size is {}.",
                        ksize, req_key_size,
                    );
                    return Err(XDPError::new(&error_msg));
                }

                Ok((map_fd, vsize, mtype, max_entries))
            }

            /// Delete an element from the underlying eBPF map.
            pub fn delete(&self, key: &K) -> XDPResult<()> {
                // Array map types do not support deletes, do an early return to save a syscall.
                if self.map_type.is_array() {
                    set_errno(Errno(22));
                    return Err(XDPError::new("Delete not supported on this map type"));
                }

                let rc = unsafe {
                    bpf::bpf_map_delete_elem(self.map_fd, key as *const _ as *const c_void)
                };

                crate::map_common::check_rc(rc, (), "Error deleting elem")
            }

            fn get_next_key(&self, prev_key: *const c_void, key: &mut K) -> XDPResult<()> {
                let rc = unsafe {
                    bpf::bpf_map_get_next_key(self.map_fd, prev_key, key as *mut _ as *mut c_void)
                };

                crate::map_common::check_rc(rc, (), "Error getting next key")
            }

            fn lookup_batch_prealloc<T>(
                &self,
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

                mc::check_rc(rc, ret, "Error looking up batch of elements")
            }
        }
    };
}

pub(crate) fn check_rc<T>(rc: i32, ret: T, err_msg: &str) -> XDPResult<T> {
    if rc < 0 {
        Err(XDPError::new(err_msg))
    } else {
        Ok(ret)
    }
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
