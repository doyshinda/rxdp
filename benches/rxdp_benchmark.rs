use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lazy_static::lazy_static;
use rxdp;
use rxdp::MapLike;

lazy_static! {
    pub static ref TEST_DATA_DIR: String = get_test_dir();
    pub static ref TEST_FILE: String = format!("{}/{}", *TEST_DATA_DIR, "test.o");
    pub static ref PIN_PATH: String = "/sys/fs/bpf".to_string();
}

pub fn get_test_dir() -> String {
    let src_dir = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    format!("{}/tests/testdata", src_dir.to_str().unwrap())
}

fn test_object() -> rxdp::XDPObject {
    rxdp::XDPObject::new(&TEST_FILE).expect("failed to test ELF file")
}

fn loaded_object() -> rxdp::XDPLoadedObject {
    test_object().load().unwrap()
}

pub fn benchmark_per_cpu_hash_map(c: &mut Criterion) {
    let obj = loaded_object();
    let m1: rxdp::PerCpuMap<u32, u32> = rxdp::PerCpuMap::new(&obj, "per_cpu_hash").unwrap();
    let key = 100u32;
    let val = 101u32;

    let delete = |m: &rxdp::PerCpuMap<u32, u32>| {
        let key = 100u32;
        let val = 0u32;
        m.update(&key, &val, rxdp::MapFlags::BpfAny).unwrap();
        m.delete(&key).unwrap();
    };

    c.bench_function("per_cpu_update_small", |b| {
        b.iter(|| black_box(m1.update(&key, &val, rxdp::MapFlags::BpfAny).unwrap()))
    });
    m1.update(&100u32, &101u32, rxdp::MapFlags::BpfAny).unwrap();
    c.bench_function("per_cpu_lookup", |b| {
        b.iter(|| black_box(m1.lookup(&100u32).unwrap()))
    });
    c.bench_function("per_cpu_delete", |b| b.iter(|| black_box(delete(&m1))));
}

pub fn benchmark_hash_map(c: &mut Criterion) {
    let obj = loaded_object();
    let mut m1: rxdp::Map<u32, u32> = rxdp::Map::new(&obj, "hash").unwrap();
    let mut m2: rxdp::Map<u32, u32> = rxdp::Map::new(&obj, "big_hash").unwrap();
    let mut keys = Vec::new();
    let mut vals = Vec::new();
    let total = m1.max_entries();
    for i in 100..(100 + total) {
        keys.push(i as u32);
        vals.push((i + 100) as u32);
    }

    let mut keys2 = Vec::new();
    let mut vals2 = Vec::new();
    let total = m2.max_entries();
    for i in 100..(100 + total) {
        keys2.push(i as u32);
        vals2.push((i + 100) as u32);
    }

    let update = |keys: &mut Vec<u32>, vals: &mut Vec<u32>, m: &mut rxdp::Map<u32, u32>| {
        let num_added = m.update_batch(keys, vals, rxdp::MapFlags::BpfAny).unwrap();
        assert_eq!(num_added, m.max_entries());
    };

    let items = |m: &rxdp::Map<u32, u32>| {
        let r = m.items().unwrap();
        assert_eq!(r.len(), m.max_entries() as usize);
    };

    let delete = |m: &mut rxdp::Map<u32, u32>| {
        let key = 100u32;
        let val = 0u32;
        m.delete(&key).unwrap();
        m.update(&key, &val, rxdp::MapFlags::BpfAny).unwrap();
    };

    c.bench_function("update_small", |b| {
        b.iter(|| black_box(update(&mut keys, &mut vals, &mut m1)))
    });
    c.bench_function("update_large", |b| {
        b.iter(|| black_box(update(&mut keys2, &mut vals2, &mut m2)))
    });
    m1.update(&100u32, &101u32, rxdp::MapFlags::BpfAny).unwrap();
    c.bench_function("items_small", |b| b.iter(|| black_box(items(&m1))));
    c.bench_function("items_large", |b| b.iter(|| black_box(items(&m2))));
    c.bench_function("lookup", |b| {
        b.iter(|| black_box(m1.lookup(&100u32).unwrap()))
    });
    c.bench_function("delete", |b| b.iter(|| black_box(delete(&mut m2))));
}

criterion_group!(benches, benchmark_hash_map, benchmark_per_cpu_hash_map);
criterion_main!(benches);
