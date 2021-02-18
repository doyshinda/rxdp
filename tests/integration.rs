use crossbeam_channel::{unbounded, Receiver, Sender};
use rxdp;
use std::collections::HashMap;
use std::path::Path;

mod utils;
use rxdp::{MapLike, MapValue};
use utils::{loaded_object, test_object};

const MAP_LRU_HASH: &'static str = "lru_hash";
const MAP_HASH: &'static str = "hash";
const MAP_HASH_BIG: &'static str = "big_hash";
const MAP_ARRAY: &'static str = "array";
const MAP_ARRAY_BIG: &'static str = "big_array";

const MAP_PERCPU_HASH: &'static str = "per_cpu_hash";
const MAP_PERCPU_HASH_BIG: &'static str = "pc_hash_big";
const MAP_PERCPU_LRU_HASH: &'static str = "per_cpu_lru";
const MAP_PERCPU_ARRAY: &'static str = "per_cpu_array";
const MAP_PERCPU_ARRAY_BIG: &'static str = "pc_array_big";

const DEV_MAP: &'static str = "dev_map";
const PERF_MAP: &'static str = "perf_event";
const PROG_TEST: &'static str = "rxdp_test";

#[test]
fn test_open_valid_elf() {
    rxdp::XDPObject::new(&utils::TEST_FILE).expect("failed to open valid ELF file");
}

#[test]
fn test_open_elf_no_such_file() {
    if let Err(e) = rxdp::XDPObject::new("missing.elf") {
        assert_eq!(e.code(), 2i32);
    } else {
        panic!("OK loading missing ELF file");
    }
}

#[test]
fn test_load() {
    let obj = test_object();
    obj.load().unwrap();
}

#[test]
fn test_pinned_maps_adds_map_to_fs() {
    let obj = test_object();
    let test_dir = utils::pin_dir();

    let mut pinned_maps = std::collections::HashSet::new();
    pinned_maps.insert(MAP_LRU_HASH.to_string());

    obj.pinned_maps(&pinned_maps, Some(&test_dir.path)).unwrap();
    obj.load().unwrap();

    let expected = format!("{}/{}", &test_dir.path, MAP_LRU_HASH);
    assert!(Path::new(&expected).exists());
}

#[test]
fn test_pinned_map_values() {
    let test_dir = utils::pin_dir();

    let mut pinned_maps = std::collections::HashSet::new();
    pinned_maps.insert(MAP_LRU_HASH.to_string());

    // Pinned map with obj1 and write a value
    let obj1 = test_object();
    obj1.pinned_maps(&pinned_maps, Some(&test_dir.path))
        .unwrap();
    let obj1 = obj1.load().unwrap();

    let m1: rxdp::Map<u32, u32> = rxdp::Map::new(&obj1, MAP_LRU_HASH).unwrap();
    let key = 100u32;
    let val = 101u32;
    m1.update(&key, &val, rxdp::MapFlags::BpfAny).unwrap();

    // Read value from obj2
    let obj2 = test_object();
    obj2.pinned_maps(&pinned_maps, Some(&test_dir.path))
        .unwrap();
    let obj2 = obj2.load().unwrap();

    let m2: rxdp::Map<u32, u32> = rxdp::Map::new(&obj2, MAP_LRU_HASH).unwrap();
    let got = m2.lookup(&key).unwrap();
    assert_eq!(val, got.into_single());
}

#[test]
fn test_pinned_per_cpu_map_values() {
    let test_dir = utils::pin_dir();

    let mut pinned_maps = std::collections::HashSet::new();
    pinned_maps.insert(MAP_PERCPU_HASH.to_string());

    // Pinned map with obj1 and write a value
    let obj1 = test_object();
    obj1.pinned_maps(&pinned_maps, Some(&test_dir.path))
        .unwrap();
    let obj1 = obj1.load().unwrap();

    let m1: rxdp::PerCpuMap<u32, u32> = rxdp::PerCpuMap::new(&obj1, MAP_PERCPU_HASH).unwrap();
    let key = 100u32;
    let val = 101u32;
    m1.update(&key, &val, rxdp::MapFlags::BpfAny).unwrap();

    // Read value from obj2
    let obj2 = test_object();
    obj2.pinned_maps(&pinned_maps, Some(&test_dir.path))
        .unwrap();
    let obj2 = obj2.load().unwrap();

    let m2: rxdp::PerCpuMap<u32, u32> = rxdp::PerCpuMap::new(&obj2, MAP_PERCPU_HASH).unwrap();
    let got = m2.lookup(&key).unwrap();

    let expected = vec![val; rxdp::num_cpus()];
    assert_eq!(got.into_vec(), expected);
}

#[test]
fn test_pinned_maps_default_path() {
    let obj = test_object();
    let mut pinned_maps = std::collections::HashSet::new();
    pinned_maps.insert(MAP_LRU_HASH.to_string());
    obj.pinned_maps(&pinned_maps, None).unwrap();
    obj.load().unwrap();

    let map_path = format!("{}/{}", *utils::PIN_PATH, MAP_LRU_HASH);
    assert!(Path::new(&map_path).exists());
    std::fs::remove_file(map_path).unwrap();
}

#[test]
fn test_no_pinned_maps() {
    let _obj = loaded_object();

    let map_path = format!("{}/{}", *utils::PIN_PATH, MAP_LRU_HASH);
    assert!(!Path::new(&map_path).exists());
}

#[test]
fn test_get_program_names() {
    let obj = loaded_object();

    let mut found = false;
    for name in obj.get_program_names() {
        if name == PROG_TEST {
            found = true;
            break;
        }
    }

    assert!(found);
}

#[test]
fn test_get_program() {
    let obj = loaded_object();
    obj.get_program(PROG_TEST)
        .expect("Unable to load test program");
}

#[test]
fn test_attach_program_to_interface() {
    let obj = loaded_object();
    let prog = obj.get_program(PROG_TEST).unwrap();

    let iface = utils::test_iface();
    prog.attach_to_interface(&iface.name, rxdp::AttachFlags::SKB_MODE)
        .unwrap();
}

#[test]
fn test_attach_program_unsupported_mode() {
    let obj = loaded_object();
    let prog = obj.get_program(PROG_TEST).unwrap();

    let iface = utils::test_iface();
    assert!(prog
        .attach_to_interface(&iface.name, rxdp::AttachFlags::HW_MODE)
        .is_err());
}

#[test]
fn test_attach_program_no_interface() {
    let obj = loaded_object();
    let prog = obj.get_program(PROG_TEST).unwrap();

    let iface = utils::random_string();
    if let Err(e) = prog.attach_to_interface(&iface, rxdp::AttachFlags::SKB_MODE) {
        assert_eq!(e.code(), 19);
    } else {
        panic!("Attach to non-existent interface succeeded");
    }
}

#[test]
fn test_create_hash_map() {
    let m = rxdp::Map::<u32, u32>::create(rxdp::MapType::Hash, 4, 4, 10, 0).unwrap();
    let key = 100u32;
    let val = 101u32;
    test_map_operations(&m, key, val);
}

#[test]
fn test_create_array_map() {
    let m = rxdp::Map::<u32, u32>::create(rxdp::MapType::Array, 4, 4, 10, 0).unwrap();
    let key = 0u32;
    let val = 101u32;
    test_map_operations(&m, key, val);
}

#[test]
fn test_lru_hash_map_operations() {
    let obj = loaded_object();
    let m: rxdp::Map<u32, u32> = rxdp::Map::new(&obj, MAP_LRU_HASH).unwrap();
    let key = 100u32;
    let val = 101u32;
    test_map_operations(&m, key, val);
}

#[test]
fn test_hash_map_operations() {
    let obj = loaded_object();
    let m: rxdp::Map<u32, u32> = rxdp::Map::new(&obj, MAP_HASH).unwrap();
    let key = 100u32;
    let val = 101u32;
    test_map_operations(&m, key, val);
}

#[test]
fn test_array_map_operations() {
    let obj = loaded_object();
    let m: rxdp::Map<u32, u32> = rxdp::Map::new(&obj, MAP_ARRAY).unwrap();
    let key = 0u32;
    let val = 100u32;
    test_map_operations(&m, key, val);
}

#[test]
fn test_dev_map_operations() {
    let obj = loaded_object();

    let iface = utils::test_iface();
    let m: rxdp::Map<u32, i32> = rxdp::Map::new(&obj, DEV_MAP).unwrap();
    let key = 0u32;
    let index = utils::lookup_interface_by_name(&iface.name).unwrap();
    test_map_operations(&m, key, index);
}

#[test]
fn test_create_per_cpu_hash_map() {
    let m = rxdp::PerCpuMap::<u32, u32>::create(rxdp::MapType::PerCPUHash, 4, 4, 10, 0).unwrap();
    let key = 100u32;
    let val = 101u32;
    test_map_operations(&m, key, val);
}

#[test]
fn test_create_per_cpu_array_map() {
    let m = rxdp::PerCpuMap::<u32, u32>::create(rxdp::MapType::PerCPUArray, 4, 4, 10, 0).unwrap();
    let key = 0u32;
    let val = 101u32;
    test_map_operations(&m, key, val);
}

#[test]
fn test_create_normal_hash_fails() {
    let r = rxdp::PerCpuMap::<u32, u32>::create(rxdp::MapType::Hash, 4, 4, 10, 0);
    assert!(r.is_err());
}

#[test]
fn test_per_cpu_lru_hash_map_operations() {
    let obj = loaded_object();
    let m: rxdp::PerCpuMap<u32, u32> = rxdp::PerCpuMap::new(&obj, MAP_PERCPU_LRU_HASH).unwrap();
    let key = 100u32;
    let val = 101u32;
    test_map_operations(&m, key, val);
}

#[test]
fn test_per_cpu_hash_map_operations() {
    let obj = loaded_object();
    let m: rxdp::PerCpuMap<u32, u32> = rxdp::PerCpuMap::new(&obj, MAP_PERCPU_HASH).unwrap();
    let key = 100u32;
    let val = 101u32;
    test_map_operations(&m, key, val);
}

#[test]
fn test_per_cpu_array_map_operations() {
    let obj = loaded_object();
    let m: rxdp::PerCpuMap<u32, u32> = rxdp::PerCpuMap::new(&obj, MAP_PERCPU_ARRAY).unwrap();
    let key = 0u32;
    let val = 100u32;
    test_map_operations(&m, key, val);
}

#[test]
fn test_items_hash_map() {
    let obj = loaded_object();
    let m: rxdp::Map<u32, u32> = rxdp::Map::new(&obj, MAP_HASH).unwrap();
    test_items(&m);
}

#[test]
fn test_items_array_map() {
    let obj = loaded_object();
    let m: rxdp::Map<u32, u32> = rxdp::Map::new(&obj, MAP_ARRAY).unwrap();
    test_items(&m);
}

#[test]
fn test_items_big_hash_map() {
    let obj = loaded_object();
    let m: rxdp::Map<u32, u32> = rxdp::Map::new(&obj, MAP_HASH_BIG).unwrap();
    test_items(&m);
}

#[test]
fn test_items_big_array_map() {
    let obj = loaded_object();
    let m: rxdp::Map<u32, u32> = rxdp::Map::new(&obj, MAP_ARRAY_BIG).unwrap();
    test_items(&m);
}

#[test]
fn test_items_per_cpu_hash_map() {
    let obj = loaded_object();
    let m: rxdp::PerCpuMap<u32, u32> = rxdp::PerCpuMap::new(&obj, MAP_PERCPU_HASH).unwrap();
    test_items(&m);
}

#[test]
fn test_items_per_cpu_array_map() {
    let obj = loaded_object();
    let m: rxdp::PerCpuMap<u32, u32> = rxdp::PerCpuMap::new(&obj, MAP_PERCPU_ARRAY).unwrap();
    test_items(&m);
}

#[test]
fn test_items_per_cpu_big_hash_map() {
    let obj = loaded_object();
    let m: rxdp::PerCpuMap<u32, u32> = rxdp::PerCpuMap::new(&obj, MAP_PERCPU_HASH_BIG).unwrap();
    test_items(&m);
}

#[test]
fn test_items_per_cpu_big_array_map() {
    let obj = loaded_object();
    let m: rxdp::PerCpuMap<u32, u32> = rxdp::PerCpuMap::new(&obj, MAP_PERCPU_ARRAY_BIG).unwrap();
    test_items(&m);
}

#[test]
fn test_perf_map_invalid_map_type() {
    let obj = loaded_object();
    let m = rxdp::PerfMap::<u32>::new(&obj, MAP_HASH);
    assert!(m.is_err());
}

#[test]
fn test_perf_map_no_sender() {
    let obj = loaded_object();
    let m = rxdp::PerfMap::<u32>::new(&obj, PERF_MAP).unwrap();
    assert!(m.poll(10).is_err());
}

#[test]
fn test_perf_map_events_crossbeam_channel() {
    let obj = loaded_object();
    let mut m = rxdp::PerfMap::<u32>::new(&obj, PERF_MAP).unwrap();

    let (s, r): (Sender<rxdp::PerfEvent<u32>>, Receiver<rxdp::PerfEvent<u32>>) = unbounded();
    m.set_sender(s);

    let num_events = 10;
    let receiver = std::thread::spawn(move || {
        for _ in 0..num_events {
            r.recv().unwrap();
        }
    });

    let pair = utils::VethPair::new("192.168.100.2", "192.168.100.3");
    let prog = obj.get_program("rxdp_perf").unwrap();
    prog.attach_to_interface(&pair.one.name, rxdp::AttachFlags::SKB_MODE)
        .unwrap();

    for _ in 0..num_events {
        pair.two.ping(&pair.one.ip, 1);
        m.poll(10).unwrap();
    }
    receiver.join().expect("Error joining receiver thread");
}

fn test_items(m: &dyn MapLike<u32, u32>) {
    let mut keys = Vec::new();
    let mut vals = Vec::new();
    let total = m.max_entries();
    for i in 0..total {
        keys.push(i as u32);
        vals.push((i + 100) as u32);
    }

    let num_added = m
        .update_batch(&mut keys, &mut vals, rxdp::MapFlags::BpfAny)
        .unwrap();
    assert_eq!(num_added, total);

    for _ in 0..2 {
        let items = m.items().unwrap();
        assert_eq!(items.len(), total as usize);

        let mut verify = HashMap::new();

        for kv in items {
            let v = match kv.value {
                MapValue::Single(v) => {
                    assert_eq!(kv.key + 100, v);
                    v
                }
                MapValue::Multi(v) => {
                    assert_eq!(v.len(), rxdp::num_cpus());
                    v[0]
                }
            };

            verify.insert(kv.key, v);
        }

        for i in 0..total {
            let (k, v) = verify.get_key_value(&i).unwrap();
            assert_eq!(*k + 100, *v);
        }
    }
}

fn test_map_operations<K, V>(m: &dyn MapLike<K, V>, key: K, val: V)
where
    K: Default + Copy + std::cmp::PartialEq + std::fmt::Debug,
    V: Default + Copy + std::cmp::PartialEq + std::fmt::Debug,
{
    let is_array = m.map_type().is_array();

    if !is_array {
        let r = m.lookup(&key);
        assert!(r.is_err());
    }

    let num_items = m.items().unwrap().len();
    if is_array {
        assert_eq!(num_items, m.max_entries() as usize);
    } else {
        // No items in map
        assert_eq!(num_items, 0);
    }

    m.update(&key, &val, rxdp::MapFlags::BpfAny).unwrap();
    let got = m.lookup(&key).unwrap();
    assert_eq!(val, got.into_single());

    if !is_array {
        for kv in m.items().unwrap() {
            assert_eq!(kv.key, key);
            match kv.value {
                MapValue::Single(v) => assert_eq!(v, val),
                MapValue::Multi(v) => {
                    assert_eq!(v.len(), rxdp::num_cpus());
                    assert_eq!(v[0], val);
                }
            }
        }
    }

    let del_resp = m.delete(&key);
    if !is_array {
        assert!(del_resp.is_ok());
        let r = m.lookup(&key);
        assert!(r.is_err());
    } else {
        assert!(del_resp.is_err());
    }

    if m.map_type() != rxdp::MapType::DevMap
        && m.map_type() != rxdp::MapType::PerCPUArray
        && rxdp::is_batching_supported()
    {
        test_batch_operations(m, key, val, is_array);
    }
}

fn test_batch_operations<K, V>(m: &dyn MapLike<K, V>, key: K, val: V, is_array: bool)
where
    K: Default + Copy + std::cmp::PartialEq + std::fmt::Debug,
    V: Default + Copy + std::cmp::PartialEq + std::fmt::Debug,
{
    let mut keys = Vec::new();
    let mut vals = Vec::new();
    keys.push(key);
    vals.push(val);

    m.update_batch(&mut keys, &mut vals, rxdp::MapFlags::BpfAny)
        .unwrap();

    let mut received = 0;
    let mut next_key = None;
    let expected = match is_array {
        true => m.max_entries(),
        _ => 1,
    };
    while received < expected {
        let r = m.lookup_batch(10u32, next_key).unwrap();
        received += r.num_items;
        for kv in r.items {
            match kv.value {
                MapValue::Single(v) => {
                    if !is_array {
                        assert_eq!(kv.key, key);
                        assert_eq!(v, val);
                    }
                }
                MapValue::Multi(v) => {
                    assert_eq!(v.len(), rxdp::num_cpus());
                    if !is_array {
                        assert_eq!(kv.key, key);
                        assert_eq!(v[0], val);
                    }
                }
            }
        }
        next_key = r.next_key;
    }

    assert_eq!(received, expected);

    if !is_array {
        let mut received = 0;
        let mut next_key = None;
        while received < expected {
            let r = m.lookup_and_delete_batch(10u32, next_key).unwrap();
            for kv in r.items {
                match kv.value {
                    MapValue::Single(v) => {
                        assert_eq!(kv.key, key);
                        assert_eq!(v, val);
                    }
                    MapValue::Multi(v) => {
                        assert_eq!(v.len(), rxdp::num_cpus());
                        assert_eq!(kv.key, key);
                        assert_eq!(v[0], val);
                    }
                }
            }
            received += r.num_items;
            next_key = r.next_key;
        }

        assert_eq!(received, expected);

        let items = m.items().unwrap();
        assert!(items.is_empty());
    }
}
