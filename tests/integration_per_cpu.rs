use rxdp;
use std::collections::HashMap;

mod utils;
use utils::{loaded_object, test_object};

const MAP_PERCPU_HASH: &'static str = "per_cpu_hash";
const MAP_PERCPU_HASH_BIG: &'static str = "pc_hash_big";
const MAP_PERCPU_LRU_HASH: &'static str = "per_cpu_lru";
const MAP_PERCPU_ARRAY: &'static str = "per_cpu_array";
const MAP_PERCPU_ARRAY_BIG: &'static str = "pc_array_big";

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

    let expected = vec![val; *rxdp::NUM_CPUS];
    assert_eq!(got, expected);
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
fn test_items_per_cpu_hash_map() {
    test_items(MAP_PERCPU_HASH);
}

#[test]
fn test_items_per_cpu_array_map() {
    test_items(MAP_PERCPU_ARRAY);
}

#[test]
fn test_items_per_cpu_big_hash_map() {
    test_items(MAP_PERCPU_HASH_BIG);
}

#[test]
fn test_items_per_cpu_big_array_map() {
    test_items(MAP_PERCPU_ARRAY_BIG);
}

#[test]
fn test_per_cpu_hash_map_batch_operations() {
    if !*rxdp::BATCHING_SUPPORTED {
        return;
    }
    let obj = loaded_object();
    let m: rxdp::PerCpuMap<u32, u32> = rxdp::PerCpuMap::new(&obj, MAP_PERCPU_HASH).unwrap();
    let mut keys = Vec::new();
    let mut vals = Vec::new();
    let total = m.max_entries;
    for i in 100..(100 + total) {
        keys.push(i as u32);
        vals.push((i + 100) as u32);
    }

    let num_added = m
        .update_batch(&mut keys, &mut vals, rxdp::MapFlags::BpfAny)
        .unwrap();
    assert_eq!(num_added, total);

    let mut received = 0;
    let mut next_key = None;
    let batch_size = 5;
    while received < total {
        let r = m.lookup_batch(batch_size, next_key).unwrap();
        received += r.num_items;
        for kv in r.items {
            assert_eq!(kv.value.len(), *rxdp::NUM_CPUS);
            assert_eq!(kv.key + 100, kv.value[0]);
        }
        next_key = r.next_key;
    }

    assert_eq!(received, total);

    let mut received = 0;
    let mut next_key = None;
    while received < total {
        let r = m.lookup_and_delete_batch(batch_size, next_key).unwrap();
        received += r.num_items;
        for kv in r.items {
            assert_eq!(kv.value.len(), *rxdp::NUM_CPUS);
            assert_eq!(kv.key + 100, kv.value[0]);
        }
        next_key = r.next_key;
    }

    assert_eq!(received, total);
    let items = m.items().unwrap();
    assert!(items.is_empty());
}

fn test_items(map_name: &str) {
    let obj = loaded_object();
    let m: rxdp::PerCpuMap<u32, u32> = rxdp::PerCpuMap::new(&obj, map_name).unwrap();
    let mut keys = Vec::new();
    let mut vals = Vec::new();
    let total = m.max_entries;
    for i in 0..total {
        keys.push(i as u32);
        vals.push((i + 100) as u32);
    }

    m.update_batch(&mut keys, &mut vals, rxdp::MapFlags::BpfAny)
        .unwrap();

    for _ in 0..2 {
        let items = m.items().unwrap();
        assert_eq!(items.len(), total as usize);

        let mut verify = HashMap::new();

        for kv in items {
            assert_eq!(kv.value.len(), *rxdp::NUM_CPUS);
            assert_eq!(kv.key + 100, kv.value[0]);
            verify.insert(kv.key, kv.value[0]);
        }

        for i in 0..total {
            let (k, v) = verify.get_key_value(&i).unwrap();
            assert_eq!(*k + 100, *v);
        }
    }
}

fn test_map_operations<K, V>(m: &rxdp::PerCpuMap<K, V>, key: K, val: V)
where
    K: Default + Copy + std::cmp::PartialEq + std::fmt::Debug,
    V: Default + Clone + std::cmp::PartialEq + std::fmt::Debug + rxdp::ByteAligned,
{
    let is_array = match m.map_type {
        rxdp::MapType::Array
        | rxdp::MapType::PerCPUArray
        | rxdp::MapType::ArrayOfMaps
        | rxdp::MapType::ProgArray
        | rxdp::MapType::PerfEventArray => true,
        _ => false,
    };

    if !is_array {
        let r = m.lookup(&key);
        assert!(r.is_err());
    }

    let num_items = m.items().unwrap().len();
    if is_array {
        assert_eq!(num_items, m.max_entries as usize);
    } else {
        // No items in map
        assert_eq!(num_items, 0);
    }

    m.update(&key, &val, rxdp::MapFlags::BpfAny).unwrap();
    let got = m.lookup(&key).unwrap();
    assert_eq!(vec![val; *rxdp::NUM_CPUS], got);

    if !is_array {
        for kv in m.items().unwrap() {
            assert_eq!(kv.key, key);
            assert_eq!(kv.value.len(), *rxdp::NUM_CPUS);
            assert_eq!(kv.value[0], val);
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

    if !is_array && *rxdp::BATCHING_SUPPORTED {
        test_batch_operations(m, key, val, is_array);
    }
}

fn test_batch_operations<K, V>(m: &rxdp::PerCpuMap<K, V>, key: K, val: V, is_array: bool)
where
    K: Default + Copy + std::cmp::PartialEq + std::fmt::Debug,
    V: Default + Clone + std::cmp::PartialEq + std::fmt::Debug + rxdp::ByteAligned,
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
        true => m.max_entries,
        _ => 1,
    };
    while received < expected {
        let r = m.lookup_batch(10u32, next_key).unwrap();
        received += r.num_items;
        next_key = r.next_key;
    }

    assert_eq!(received, expected);

    if !is_array {
        let mut received = 0;
        let mut next_key = None;
        while received < expected {
            let r = m.lookup_and_delete_batch(10u32, next_key).unwrap();
            for kv in r.items {
                assert_eq!(kv.value.len(), *rxdp::NUM_CPUS);
            }
            received += r.num_items;
            next_key = r.next_key;
        }

        assert_eq!(received, expected);

        let items = m.items().unwrap();
        assert!(items.is_empty());
    }
}
