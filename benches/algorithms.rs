use bloomfilter::Bloom;
use criterion::{criterion_group, criterion_main, Criterion};
use std::net::Ipv4Addr;

use clash_rules::*;
use rand::distr::Alphanumeric;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::Rng;
use rand::SeedableRng;
use std::collections::HashMap;
pub fn get_test_ips() -> Vec<Ipv4Addr> {
    vec![
        Ipv4Addr::new(1, 2, 3, 4),
        Ipv4Addr::new(2, 2, 3, 4),
        Ipv4Addr::new(3, 2, 3, 4),
        Ipv4Addr::new(15, 207, 213, 128),
    ]
}
pub fn get_test_domains() -> Vec<&'static str> {
    vec![
        "www.google.com",
        "jdj.reddit.com",
        "hdjd.baidu.com",
        "hshsh.djdjdj.djdj",
    ]
}
pub fn generate_test_domains(rules: &Vec<Vec<String>>, seed: u64) -> Vec<String> {
    let mut v = vec![];
    for x in rules {
        let domain = x.first().unwrap();
        v.push(domain.clone());
    }
    let random_item_count = v.len() * 2;

    fn generate_strings(vec: &mut Vec<String>, n: usize, length: usize, seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        for _ in 0..n {
            let s: String = (0..length)
                .map(|_| rng.sample(Alphanumeric) as char)
                .collect();
            vec.push(s);
        }
    }

    generate_strings(&mut v, random_item_count, 20, seed);
    let mut rng = StdRng::seed_from_u64(seed);
    v.shuffle(&mut rng);

    v
}
pub fn check_match_dummy2<'a>(
    haystack: &'a HashMap<&str, Vec<&str>>,
    needle: &str,
) -> Option<&'a str> {
    for (target, items) in haystack {
        for v in items {
            if needle.eq(*v) {
                return Some(*target);
            }
        }
    }
    None
}
/// 只适用于 DOMAIN
pub fn get_rule_bloom(rules: &Vec<Vec<String>>) -> Bloom<&String> {
    let num_items = rules.len();
    let fp_rate = 0.1;

    let mut bloom = Bloom::new_for_fp_rate(num_items, fp_rate).unwrap();
    for x in rules {
        let d = x.first().unwrap();
        bloom.set(&d);
    }
    bloom
}
fn bench_domain(c: &mut Criterion) {
    let hashmap = parse_rules(&load_rules_from_file("test.yaml").unwrap());

    let v = get_domain_rules(&hashmap).unwrap();
    let ds = generate_test_domains(v, 0);
    let bloom = get_rule_bloom(v);
    // let map = get_target_item_map(v);
    let map2 = get_item_target_map(v);
    // 因为 dummy 本来就直接是  哈希，因此 bloom 多此一举，效率不如直接 dummy
    c.bench_function("dummy2_domain_with_bloom", |b| {
        b.iter(|| {
            ds.iter().for_each(|d| {
                if bloom.check(&d) {
                    map2.get(d);
                }
            });
        })
    });
    // domain 的match 匹配时，trie性能不如dummy, 因为没有预先过滤长度
    // let trie = get_normal_trie(&map);
    // c.bench_function("trie_domain", |b| {
    //     b.iter(|| {
    //         ss.iter().for_each(|s| {
    //             check_normal_trie(&trie, s);
    //         });
    //     })
    // });
    // dummy2 也明显不如 dummy
    // c.bench_function("dummy_domain", |b| {
    //     b.iter(|| {
    //         ss.iter().for_each(|s| {
    //             check_match_dummy2(&map, s);
    //         });
    //     })
    // });
    c.bench_function("dummy2_domain", |b| {
        b.iter(|| {
            ds.iter().for_each(|d| {
                map2.get(d);
            });
        })
    });
}
fn bench_suffix(c: &mut Criterion) {
    let hashmap = parse_rules(&load_rules_from_file("test.yaml").unwrap());

    let v = get_suffix_rules(&hashmap).unwrap();
    let map = get_target_item_map(v);
    let ds = get_test_domains();
    let trie = gen_suffix_trie(&map);
    c.bench_function("trie_suffix", |b| {
        b.iter(|| {
            ds.iter().for_each(|d| {
                check_suffix_trie(&trie, d);
            });
        })
    });
    c.bench_function("dummy_suffix", |b| {
        b.iter(|| {
            ds.iter().for_each(|d| {
                check_suffix_dummy(&map, d);
            });
        })
    });
}
fn bench_keyword(c: &mut Criterion) {
    let hashmap = parse_rules(&load_rules_from_file("test.yaml").unwrap());

    let v = get_keyword_rules(&hashmap).unwrap();
    let map = get_target_item_map(v);
    let ds = get_test_domains();
    let ac = gen_keywords_ac(&map);
    let ac2 = gen_keywords_ac2(v);
    let targets = get_keywords_targets(v);

    c.bench_function("ac", |b| {
        b.iter(|| {
            ds.iter().for_each(|d| {
                check_keyword_ac(&ac, d);
            });
        })
    });
    c.bench_function("ac2", |b| {
        b.iter(|| {
            ds.iter().for_each(|d| {
                check_keyword_ac2(&ac2, d, &targets);
            });
        })
    });
    c.bench_function("dummy_keyword", |b| {
        b.iter(|| {
            ds.iter().for_each(|s| {
                check_keyword_dummy(&map, s);
            });
        })
    });
}

fn bench_ip(c: &mut Criterion) {
    let rule_map = parse_rules(&load_rules_from_file("test.yaml").unwrap());

    let ip_rules = get_ip_cidr_rules(&rule_map).unwrap();
    let ip_map = get_target_item_map(ip_rules);
    let it = gen_ip_trie(&ip_map);
    let it2 = gen_ip_trie2(&ip_map);

    let ips = get_test_ips();

    c.bench_function("trie_ip", |b| {
        b.iter(|| {
            ips.iter().for_each(|ip| {
                check_ip_trie(&it, *ip);
            });
        })
    });
    // Trie 包是使用的通用的字节向量，其效率不如按位的Prefix-trie 包高
    c.bench_function("trie2_ip", |b| {
        b.iter(|| {
            ips.iter().for_each(|ip| {
                check_ip_trie2(&it2, *ip);
            });
        })
    });
}

criterion_group!(benches, bench_ip, bench_domain, bench_suffix, bench_keyword);
criterion_main!(benches);
