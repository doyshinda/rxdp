use libbpf_sys as bpf;

/// Flags that control map `update` behaviour.
#[derive(Copy, Clone)]
#[repr(u32)]
pub enum MapFlags {
    /// Create a new element or update an existing element.
    BpfAny = bpf::BPF_ANY,

    /// Create a new element only if it did not exist.
    BpfNoExist = bpf::BPF_NOEXIST,

    /// Update an existing element.
    BpfExist = bpf::BPF_EXIST,
}
