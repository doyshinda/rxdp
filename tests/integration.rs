use rxdp;
use std::path::Path;
use std::collections::HashMap;

mod utils;
use utils::{test_object, loaded_object};

const MAP_LRU_HASH: &'static str = "lru_hash";
const MAP_HASH: &'static str = "hash";
const MAP_HASH_BIG: &'static str = "big_hash";
const MAP_ARRAY: &'static str = "array";
const MAP_ARRAY_BIG: &'static str = "big_array";
const DEV_MAP: &'static str = "dev_map";
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
    obj1.pinned_maps(&pinned_maps, Some(&test_dir.path)).unwrap();
    let obj1 = obj1.load().unwrap();

    let m1: rxdp::Map<u32, u32> = rxdp::Map::new(&obj1, MAP_LRU_HASH).unwrap();
    let key = 100u32;
    let val = 101u32;
    m1.update(&key, &val, rxdp::MapFlags::BpfAny).unwrap();

    // Read value from obj2
    let obj2 = test_object();
    obj2.pinned_maps(&pinned_maps, Some(&test_dir.path)).unwrap();
    let obj2 = obj2.load().unwrap();

    let m2: rxdp::Map<u32, u32> = rxdp::Map::new(&obj2, MAP_LRU_HASH).unwrap();
    let got = m2.lookup(&key).unwrap();
    assert_eq!(val, got);
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
    obj.get_program(PROG_TEST).expect("Unable to load test program");
}

#[test]
fn test_attach_program_to_interface() {
    let obj = loaded_object();
    let prog = obj.get_program(PROG_TEST).unwrap();

    let iface = utils::test_iface();
    prog.attach_to_interface(&iface.name, rxdp::AttachFlags::SKB_MODE).unwrap();
}

#[test]
fn test_attach_program_unsupported_mode() {
    let obj = loaded_object();
    let prog = obj.get_program(PROG_TEST).unwrap();

    let iface = utils::test_iface();
    if let Err(e) = prog.attach_to_interface(&iface.name, rxdp::AttachFlags::HW_MODE) {
       assert_eq!(e.code(), 2);
    } else {
        panic!("Attach for non-supported mode succeeded");
    }
}

#[test]
fn test_attach_program_no_interface() {
    let obj = loaded_object();
    let prog = obj.get_program(PROG_TEST).unwrap();

    let iface = utils::random_string();
    if let Err(e) =  prog.attach_to_interface(&iface, rxdp::AttachFlags::SKB_MODE) {
        assert_eq!(e.code(), 19);
    } else {
        panic!("Attach to non-existent interface succeeded");
    }
}

#[test]
fn test_create_hash_map() {
    let m = rxdp::Map::<u32, u32>::create(
        rxdp::MapType::Hash,
        4,
        4,
        10,
        0,
    ).unwrap();
    let key = 100u32;
    let val = 101u32;
    test_map_operations(&m, key, val);
}

#[test]
fn test_create_array_map() {
    let m = rxdp::Map::<u32, u32>::create(
        rxdp::MapType::Array,
        4,
        4,
        10,
        0,
    ).unwrap();
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
fn test_hash_map_batch_operations() {
    let obj = loaded_object();
    let m: rxdp::Map<u32, u32> = rxdp::Map::new(&obj, MAP_HASH).unwrap();
    if !m.batching_supported() {
        return;
    }
    let mut keys = Vec::new();
    let mut vals = Vec::new();
    let batch_size = 10;
    let total = m.max_entries;
    for i in 100..(100 + total) {
        keys.push(i as u32);
        vals.push((i + 100) as u32);
    }

    let num_added = m.update_batch(&mut keys, &mut vals, rxdp::MapFlags::BpfAny).unwrap();
    assert_eq!(num_added, total);

    let mut received = 0;
    let mut next_key = None;
    while received < total {
        let r = m.lookup_batch(batch_size, next_key).unwrap();
        received += r.num_items;
        for kv in r.items {
            assert_eq!(kv.key + 100, kv.value);
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
            assert_eq!(kv.key + 100, kv.value);
        }
        next_key = r.next_key;
    }

    assert_eq!(received, total);
    let items = m.items().unwrap();
    assert!(items.is_empty());
}

#[test]
fn test_items_hash_map() {
    test_items(MAP_HASH);
}

#[test]
fn test_items_array_map() {
    test_items(MAP_ARRAY);
}

#[test]
fn test_items_big_hash_map() {
    test_items(MAP_HASH_BIG);
}

#[test]
fn test_items_big_array_map() {
    test_items(MAP_ARRAY_BIG);
}

fn test_items(map_name: &str) {
    let obj = loaded_object();
    let m: rxdp::Map<u32, u32> = rxdp::Map::new(&obj, map_name).unwrap();
    let mut keys = Vec::new();
    let mut vals = Vec::new();
    let total = m.max_entries;
    for i in 0..total {
        keys.push(i as u32);
        vals.push((i + 100) as u32);
    }

    let num_added = update_batch(&m, &mut keys, &mut vals);
    assert_eq!(num_added, total);

    for _ in 0..2 {
        let items = m.items().unwrap();
        assert_eq!(items.len(), total as usize);

        let mut verify = HashMap::new();

        for kv in items {
            assert_eq!(kv.key + 100, kv.value);
            verify.insert(kv.key, kv.value);
        }

        for i in 0..total {
            let (k, v) = verify.get_key_value(&i).unwrap();
            assert_eq!(*k + 100, *v);
        }
    }
}


fn test_map_operations<K, V>(m: &rxdp::Map<K, V>, key: K, val: V)
where
    K: Default + Copy + std::cmp::PartialEq + std::fmt::Debug,
    V: Default + std::cmp::PartialEq + std::fmt::Debug,
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
    assert_eq!(val, got);

    if !is_array {
        for kv in m.items().unwrap() {
            assert_eq!(kv.key, key);
            assert_eq!(kv.value, val);
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


    if m.map_type != rxdp::MapType::DevMap && m.batching_supported() {
        test_batch_operations(m, key, val, is_array);
    }
}

fn test_batch_operations<K, V>(m: &rxdp::Map<K, V>, key: K, val: V, is_array: bool)
where
    K: Default + Copy + std::cmp::PartialEq + std::fmt::Debug,
    V: Default + std::cmp::PartialEq + std::fmt::Debug,
{
    let mut keys = Vec::new();
    let mut vals = Vec::new();
    keys.push(key);
    vals.push(val);
    m.update_batch(&mut keys, &mut vals, rxdp::MapFlags::BpfAny).unwrap();

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
            received += r.num_items;
            next_key = r.next_key;
        }

        assert_eq!(received, expected);

        let items = m.items().unwrap();
        assert!(items.is_empty());
    }
}

fn update_batch<K, V>(m: &rxdp::Map<K, V>, keys: &mut Vec<K>, vals: &mut Vec<V>) -> u32
where
    K: Default + Copy + std::cmp::PartialEq + std::fmt::Debug,
    V: Default + std::cmp::PartialEq + std::fmt::Debug,
{
    m.update_batch(keys, vals, rxdp::MapFlags::BpfAny).unwrap();
    return keys.len() as u32;
}
