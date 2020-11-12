#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum MapType {
    Unspec = libbpf_sys::BPF_MAP_TYPE_UNSPEC,
    Hash = libbpf_sys::BPF_MAP_TYPE_HASH,
    Array = libbpf_sys::BPF_MAP_TYPE_ARRAY,
    ProgArray = libbpf_sys::BPF_MAP_TYPE_PROG_ARRAY,
    PerfEventArray = libbpf_sys::BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    PerCPUHash = libbpf_sys::BPF_MAP_TYPE_PERCPU_HASH,
    PerCPUArray = libbpf_sys::BPF_MAP_TYPE_PERCPU_ARRAY,
    StackTrace = libbpf_sys::BPF_MAP_TYPE_STACK_TRACE,
    CgroupArray = libbpf_sys::BPF_MAP_TYPE_CGROUP_ARRAY,
    LRUHash = libbpf_sys::BPF_MAP_TYPE_LRU_HASH,
    LRUPerCPUHash = libbpf_sys::BPF_MAP_TYPE_LRU_PERCPU_HASH,
    LPMTrie = libbpf_sys::BPF_MAP_TYPE_LPM_TRIE,
    ArrayOfMaps = libbpf_sys::BPF_MAP_TYPE_ARRAY_OF_MAPS,
    HashOfMaps = libbpf_sys::BPF_MAP_TYPE_HASH_OF_MAPS,
    DevMap = libbpf_sys::BPF_MAP_TYPE_DEVMAP,
    SockMap = libbpf_sys::BPF_MAP_TYPE_SOCKMAP,
    CPUMap = libbpf_sys::BPF_MAP_TYPE_CPUMAP,
    XSKMap = libbpf_sys::BPF_MAP_TYPE_XSKMAP,
    SockHash = libbpf_sys::BPF_MAP_TYPE_SOCKHASH,
    CgroupStorage = libbpf_sys::BPF_MAP_TYPE_CGROUP_STORAGE,
    ReusePortSockArray = libbpf_sys::BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    PerCPUCgroupStorage = libbpf_sys::BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
    Queue = libbpf_sys::BPF_MAP_TYPE_QUEUE,
    Stack = libbpf_sys::BPF_MAP_TYPE_STACK,
    SKStorage = libbpf_sys::BPF_MAP_TYPE_SK_STORAGE,
    DevMapHash = libbpf_sys::BPF_MAP_TYPE_DEVMAP_HASH,
    StructOpts = libbpf_sys::BPF_MAP_TYPE_STRUCT_OPS,
    RingBuffer = libbpf_sys::BPF_MAP_TYPE_RINGBUF,
}

impl From<u32> for MapType {
    fn from(orig: u32) -> Self {
        match orig {
            0 => MapType::Unspec,
            1 => MapType::Hash,
            2 => MapType::Array,
            3 => MapType::ProgArray,
            4 => MapType::PerfEventArray,
            5 => MapType::PerCPUHash,
            6 => MapType::PerCPUArray,
            7 => MapType::StackTrace,
            8 => MapType::CgroupArray,
            9 => MapType::LRUHash,
            10 => MapType::LRUPerCPUHash,
            11 => MapType::LPMTrie,
            12 => MapType::ArrayOfMaps,
            13 => MapType::HashOfMaps,
            14 => MapType::DevMap,
            15 => MapType::SockMap,
            16 => MapType::CPUMap,
            17 => MapType::XSKMap,
            18 => MapType::SockHash,
            19 => MapType::CgroupStorage,
            20 => MapType::ReusePortSockArray,
            21 => MapType::PerCPUCgroupStorage,
            22 => MapType::Queue,
            23 => MapType::Stack,
            24 => MapType::SKStorage,
            25 => MapType::DevMapHash,
            26 => MapType::StructOpts,
            27 => MapType::RingBuffer,
            _ => MapType::Unspec,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_from_u32() {
        for i in 0..27 {
            assert_eq!(i, MapType::from(i) as u32);
        }
    }
}
