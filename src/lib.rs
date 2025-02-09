use ipnet::Ipv4Net;
use ipnet::Ipv6Net;
use prefix_trie::*;
use radix_trie::{Trie, TrieCommon};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct RuleConfig {
    pub rules: Vec<String>,
}
pub fn load_rules<P: AsRef<Path>>(path: P) -> HashMap<String, Vec<Vec<String>>> {
    let f = std::fs::read_to_string(path).unwrap();
    let x: RuleConfig = serde_yaml_ng::from_str(&f).unwrap();

    // rule, items
    let mut hashmap: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    for rule in &x.rules {
        let mut parts = rule.split(',');
        if let Some(key) = parts.next() {
            let values: Vec<String> = parts.map(|x| x.to_string()).collect();
            hashmap.entry(key.to_string()).or_default().push(values);
        }
    }
    hashmap
}

pub fn get_domain_rules(hashmap: &HashMap<String, Vec<Vec<String>>>) -> Option<&Vec<Vec<String>>> {
    hashmap.get("DOMAIN")
}
pub fn get_suffix_rules(hashmap: &HashMap<String, Vec<Vec<String>>>) -> Option<&Vec<Vec<String>>> {
    hashmap.get("DOMAIN-SUFFIX")
}
pub fn get_keyword_rules(hashmap: &HashMap<String, Vec<Vec<String>>>) -> Option<&Vec<Vec<String>>> {
    hashmap.get("DOMAIN-KEYWORD")
}
pub fn get_ip_cidr_rules(hashmap: &HashMap<String, Vec<Vec<String>>>) -> Option<&Vec<Vec<String>>> {
    hashmap.get("IP-CIDR")
}
pub fn get_ip6_cidr_rules(
    hashmap: &HashMap<String, Vec<Vec<String>>>,
) -> Option<&Vec<Vec<String>>> {
    hashmap.get("IP-CIDR6")
}

/// 用于 DOMAIN, PROCESS-NAME 等直接匹配的情况
pub fn get_item_target_map(rules: &Vec<Vec<String>>) -> HashMap<&str, &str> {
    let mut map: HashMap<&str, &str> = HashMap::new();
    for x in rules {
        let suffix = x.first().unwrap();
        let target = x.get(1).unwrap();
        map.insert(suffix, target);
    }
    map
}

/// 用于 SUFFIX， KEYWORD，CIDR 等需要遍历的情况
pub fn get_target_item_map(rules: &Vec<Vec<String>>) -> HashMap<&str, Vec<&str>> {
    let mut map: HashMap<&str, Vec<&str>> = HashMap::new();
    for x in rules {
        let suffix = x.first().unwrap();
        let target = x.get(1).unwrap();
        map.entry(target).or_default().push(suffix);
    }
    map
}

use aho_corasick::AhoCorasick;
pub fn get_keywords_ac(map: &HashMap<&str, Vec<&str>>) -> HashMap<String, AhoCorasick> {
    map.iter()
        .map(|x| (x.0.to_string(), AhoCorasick::new(x.1).unwrap()))
        .collect()
}

pub fn get_keywords_targets(rules: &[Vec<String>]) -> Vec<String> {
    rules.iter().filter_map(|v| v.get(1).cloned()).collect()
}
pub fn get_keywords_ac2(rules: &[Vec<String>]) -> AhoCorasick {
    let result: Vec<String> = rules.iter().filter_map(|v| v.first().cloned()).collect();

    AhoCorasick::new(&result).unwrap()
}
pub fn get_ip_trie(map: &HashMap<&str, Vec<&str>>) -> PrefixMap<Ipv4Net, usize> {
    let mut trie = PrefixMap::<Ipv4Net, usize>::new();
    for (i, (_key, value)) in map.iter().enumerate() {
        for v in value {
            let r: Ipv4Net = v.parse().unwrap();
            trie.insert(r, i);
        }
    }
    trie
}
fn u32_to_bit_u8_vec(n: u32, len: u8) -> Vec<u8> {
    (32 - len..32u8).rev().map(|i| (n >> i) as u8).collect()
}
fn ipv4net_to_vec(ipnet: &Ipv4Net) -> Vec<u8> {
    u32_to_bit_u8_vec(
        u32::from_be_bytes(ipnet.network().octets()),
        ipnet.prefix_len(),
    )
}
#[derive(PartialEq, Eq, Debug)]
pub struct MyIpv4Net(pub Ipv4Net);
impl radix_trie::TrieKey for MyIpv4Net {
    fn encode_bytes(&self) -> Vec<u8> {
        ipv4net_to_vec(&self.0)
    }
}
pub fn get_ip_trie2(map: &HashMap<&str, Vec<&str>>) -> Trie<MyIpv4Net, usize> {
    let mut trie = Trie::<MyIpv4Net, usize>::new();
    for (i, (_key, value)) in map.iter().enumerate() {
        for v in value {
            let r: Ipv4Net = v.parse().unwrap();
            trie.insert(MyIpv4Net(r), i);
        }
    }
    trie
}
pub fn get_ip6_trie(map: &HashMap<&str, Vec<&str>>) -> PrefixMap<Ipv6Net, usize> {
    let mut trie = PrefixMap::<Ipv6Net, usize>::new();
    for (i, (_key, value)) in map.iter().enumerate() {
        for v in value {
            let r: Ipv6Net = v.parse().unwrap();
            trie.insert(r, i);
        }
    }
    trie
}
pub fn get_normal_trie<'a>(map: &'a HashMap<&str, Vec<&str>>) -> Trie<&'a str, usize> {
    let mut trie = Trie::new();

    for (i, (_key, value)) in map.iter().enumerate() {
        for v in value {
            trie.insert(*v, i);
        }
    }
    trie
}

/// 逆序存储
pub fn get_suffix_trie(map: &HashMap<&str, Vec<&str>>) -> Trie<String, usize> {
    let mut trie = Trie::new();

    for (i, (_key, value)) in map.iter().enumerate() {
        for v in value {
            let r: String = v.chars().rev().collect();
            trie.insert(r, i);
        }
    }
    trie
}

pub fn check_match_dummy<'a>(
    haystack: &'a HashMap<&str, &str>,
    needle: &str,
) -> Option<&'a &'a str> {
    haystack.get(needle)
}
pub fn check_suffix_dummy<'a>(map: &'a HashMap<&str, Vec<&str>>, s: &str) -> Option<&'a str> {
    for (target, items) in map {
        for v in items {
            if s.ends_with(*v) {
                return Some(*target);
            }
        }
    }
    None
}
pub fn check_keyword_ac<'a>(map: &'a HashMap<String, AhoCorasick>, s: &str) -> Option<&'a str> {
    for (target, ac) in map {
        if ac.is_match(s) {
            return Some(target);
        }
    }
    None
}

/// faster than ac, but requries an extra targets lookup vec by get_keywords_targets
pub fn check_keyword_ac2<'a>(ac: &AhoCorasick, s: &str, targets: &'a [String]) -> Option<&'a str> {
    if let Some(mat) = ac.find_iter(s).next() {
        let keyword_index = mat.pattern();
        return Some(targets[keyword_index].as_str());
    }
    None
}
pub fn check_keyword_dummy<'a>(map: &'a HashMap<&str, Vec<&str>>, s: &str) -> Option<&'a str> {
    for (target, items) in map {
        for v in items {
            if s.contains(*v) {
                return Some(*target);
            }
        }
    }
    None
}
pub fn check_normal_trie(trie: &Trie<&str, usize>, s: &str) -> Option<usize> {
    if let Some(subtree) = trie.get_ancestor(s) {
        subtree.value().cloned()
    } else {
        None
    }
}
pub fn check_suffix_trie(trie: &Trie<String, usize>, s: &str) -> Option<usize> {
    let sr: String = s.chars().rev().collect();
    if let Some(subtree) = trie.get_ancestor(&sr) {
        subtree.value().cloned()
    } else {
        None
    }
}
pub fn check_ip_trie2(trie: &Trie<MyIpv4Net, usize>, addr: Ipv4Addr) -> Option<usize> {
    let ipn = MyIpv4Net(Ipv4Net::new(addr, 32).unwrap());
    if let Some(subtree) = trie.get_ancestor(&ipn) {
        subtree.value().cloned()
    } else {
        None
    }
}
pub fn check_ip_trie(trie: &PrefixMap<Ipv4Net, usize>, addr: Ipv4Addr) -> Option<usize> {
    trie.get_lpm(&Ipv4Net::new(addr, 32).unwrap()).map(|r| *r.1)
}
pub fn check_ip6_trie(trie: &PrefixMap<Ipv6Net, usize>, addr: Ipv6Addr) -> Option<usize> {
    trie.get_lpm(&Ipv6Net::new(addr, 32).unwrap()).map(|r| *r.1)
}

#[cfg(test)]
pub fn get_test_ips() -> Vec<Ipv4Addr> {
    vec![
        Ipv4Addr::new(1, 2, 3, 4),
        Ipv4Addr::new(2, 2, 3, 4),
        Ipv4Addr::new(3, 2, 3, 4),
        Ipv4Addr::new(15, 207, 213, 128),
    ]
}
#[cfg(test)]
pub fn get_test_domains() -> Vec<&'static str> {
    vec![
        "www.google.com",
        "jdj.reddit.com",
        "hdjd.baidu.com",
        "hshsh.djdjdj.djdj",
    ]
}
/// cargo test -- --nocapture
#[test]
fn main() {
    let rule_map = load_rules("test.yaml");

    let dr = get_domain_rules(&rule_map).unwrap();
    println!("{:?}", dr.len());
    let suffix_rules = get_suffix_rules(&rule_map).unwrap();
    println!("{:?}", suffix_rules.len());
    let suffix_map: HashMap<&str, Vec<&str>> = get_target_item_map(suffix_rules);

    let suffix_targets: Vec<&str> = suffix_map.keys().copied().collect();

    println!("{:?}", suffix_targets);
    let trie = get_suffix_trie(&suffix_map);

    let keyword_rules = get_keyword_rules(&rule_map).unwrap();
    println!("{:?}", keyword_rules.len());
    let kmap = get_target_item_map(keyword_rules);
    let ac = get_keywords_ac(&kmap);
    let ac2 = get_keywords_ac2(keyword_rules);
    let ac2_targets = get_keywords_targets(keyword_rules);

    let ss = get_test_domains();
    for s in ss {
        let r = check_suffix_trie(&trie, s);
        println!("{:?}", r.map(|i| suffix_targets.get(i).unwrap()));
        let r = check_keyword_ac(&ac, s);
        println!("{:?}", r);
        let r = check_keyword_ac2(&ac2, s, &ac2_targets);
        println!("{:?}", r);
    }

    let ip_rules = get_ip_cidr_rules(&rule_map).unwrap();
    println!("{:?}", ip_rules.len());
    let ip_map = get_target_item_map(ip_rules);
    let ip_targets: Vec<&str> = ip_map.keys().copied().collect();
    let it = get_ip_trie(&ip_map);
    let it2 = get_ip_trie2(&ip_map);

    let ips = get_test_ips();
    for ip in ips {
        let r = check_ip_trie(&it, ip);
        println!("{:?}", r.map(|i| ip_targets.get(i).unwrap()));
        let r = check_ip_trie2(&it2, ip);
        println!("{:?}", r.map(|i| ip_targets.get(i).unwrap()));
    }

    let ip_rules = get_ip6_cidr_rules(&rule_map).unwrap();
    println!("{:?}", ip_rules.len());
}
