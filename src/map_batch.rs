use lazy_static::lazy_static;
use libbpf_sys as bpf;

use crate::{KeyValue, Map, MapFlags, MapType};

pub(crate) const BATCH_SIZE: u32 = 100;
pub(crate) const BATCH_OPTS: bpf::bpf_map_batch_opts = bpf::bpf_map_batch_opts {
    sz: 24u64,
    elem_flags: 0u64,
    flags: 0u64,
};

lazy_static! {
    pub static ref BATCHING_SUPPORTED: bool = batching_supported();
}

/// The result of a batch operation.
pub struct BatchResult<K, V> {
    pub items: Vec<KeyValue<K, V>>,
    pub next_key: Option<u32>,
    pub num_items: u32,
}

pub(crate) struct BatchResultInternal {
    pub(crate) next_key: Option<u32>,
    pub(crate) num_items: u32,
}

fn batching_supported() -> bool {
    // if let Ok(v) = std::env::var(BATCH_SUPPORTED) {
    //     match v.as_str() {
    //         "0" => return false,
    //         _ => return true,
    //     }
    // }

    match Map::<u32, u32>::_create(MapType::Hash, 4, 4, 10, 0, false).and_then(|m| {
        m.update(&0u32, &0u32, MapFlags::BpfAny)
            .and_then(|_| m.lookup_batch_impl(10, None, false))
    }) {
        Err(_) => {
            // std::env::set_var(BATCH_SUPPORTED, "0");
            false
        }
        Ok(_) => {
            // std::env::set_var(BATCH_SUPPORTED, "1");
            true
        }
    }
}
