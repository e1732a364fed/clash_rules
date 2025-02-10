pub use aho_corasick::AhoCorasick;
pub use prefix_trie::PrefixMap;
pub use radix_trie::{Trie, TrieCommon};
pub use serde_yaml_ng;

use ipnet::{Ipv4Net, Ipv6Net};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct RuleSet {
    pub payload: Vec<String>,
}
#[derive(Debug)]
pub enum LoadYamlFileError {
    FileErr(std::io::Error),
    YamlErr(serde_yaml_ng::Error),
}

impl From<std::io::Error> for LoadYamlFileError {
    fn from(err: std::io::Error) -> Self {
        LoadYamlFileError::FileErr(err)
    }
}

impl From<serde_yaml_ng::Error> for LoadYamlFileError {
    fn from(err: serde_yaml_ng::Error) -> Self {
        LoadYamlFileError::YamlErr(err)
    }
}

pub fn load_rule_set_from_file<P: AsRef<Path>>(path: P) -> Result<RuleSet, LoadYamlFileError> {
    let content = std::fs::read_to_string(path)?;
    let ruleset = serde_yaml_ng::from_str(&content)?;
    Ok(ruleset)
}

pub fn parse_rule_set_as_domain_suffix_trie(
    payload: &[String],
    target_id: usize,
) -> Trie<String, usize> {
    let mut trie = Trie::new();

    for v in payload.iter() {
        let r: String = v.chars().rev().collect();
        trie.insert(r, target_id);
    }
    trie
}
pub fn parse_rule_set_as_ip_cidr_trie(
    payload: &[String],
    target_id: usize,
) -> PrefixMap<Ipv4Net, usize> {
    let mut trie = PrefixMap::<Ipv4Net, usize>::new();
    for v in payload.iter() {
        let r: Ipv4Net = v.parse().unwrap();
        trie.insert(r, target_id);
    }
    trie
}

pub fn parse_rule_set_as_classic(
    payload: &[String],
    target: String,
) -> HashMap<String, Vec<Vec<String>>> {
    let mut hashmap: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    for rule in payload {
        let mut parts = rule.split(',');
        if let Some(key) = parts.next() {
            let mut values: Vec<String> = parts.map(|part| part.to_string()).collect();
            values.insert(1, target.clone());
            hashmap.entry(key.to_string()).or_default().push(values);
        }
    }
    hashmap
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RuleConfig {
    pub rules: Vec<String>,
}
pub fn load_rules_from_file<P: AsRef<Path>>(path: P) -> Result<RuleConfig, LoadYamlFileError> {
    let f = std::fs::read_to_string(path)?;
    let rs = serde_yaml_ng::from_str(&f)?;
    Ok(rs)
}

/// parse clash rules into METHOD-rules hashmap, the ',' splitted items is pushed in the inner Vec
pub fn parse_rules(rc: &RuleConfig) -> HashMap<String, Vec<Vec<String>>> {
    // rule, items
    let mut hashmap: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    for rule in &rc.rules {
        let mut parts = rule.split(',');
        if let Some(key) = parts.next() {
            let values: Vec<String> = parts.map(|part| part.to_string()).collect();
            hashmap.entry(key.to_string()).or_default().push(values);
        }
    }
    hashmap
}

pub fn get_domain_rules(
    method_rules_map: &HashMap<String, Vec<Vec<String>>>,
) -> Option<&Vec<Vec<String>>> {
    method_rules_map.get("DOMAIN")
}
pub fn get_suffix_rules(
    method_rules_map: &HashMap<String, Vec<Vec<String>>>,
) -> Option<&Vec<Vec<String>>> {
    method_rules_map.get("DOMAIN-SUFFIX")
}
pub fn get_keyword_rules(
    method_rules_map: &HashMap<String, Vec<Vec<String>>>,
) -> Option<&Vec<Vec<String>>> {
    method_rules_map.get("DOMAIN-KEYWORD")
}
pub fn get_ip_cidr_rules(
    method_rules_map: &HashMap<String, Vec<Vec<String>>>,
) -> Option<&Vec<Vec<String>>> {
    method_rules_map.get("IP-CIDR")
}
pub fn get_ip6_cidr_rules(
    method_rules_map: &HashMap<String, Vec<Vec<String>>>,
) -> Option<&Vec<Vec<String>>> {
    method_rules_map.get("IP-CIDR6")
}

/// for DOMAIN, PROCESS-NAME etc. that matches directly
pub fn get_item_target_map(rules: &[Vec<String>]) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    for x in rules {
        let item = x.first().unwrap();
        let target = x.get(1).unwrap();
        map.insert(item.clone(), target.clone());
    }
    map
}

/// for SUFFIX， KEYWORD，CIDR etc. that require iter.
pub fn get_target_item_map(rules: &[Vec<String>]) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for part in rules {
        let item = part.first().unwrap();
        let target = part.get(1).unwrap();
        map.entry(target.clone()).or_default().push(item.clone());
    }
    map
}

pub fn get_keywords_ac(
    target_keywords_map: &HashMap<String, Vec<String>>,
) -> HashMap<String, AhoCorasick> {
    target_keywords_map
        .iter()
        .map(|(k, v)| (k.clone(), AhoCorasick::new(v).unwrap()))
        .collect()
}

pub fn get_keywords_targets(rules: &[Vec<String>]) -> Vec<String> {
    rules.iter().filter_map(|v| v.get(1).cloned()).collect()
}
pub fn get_keywords_ac2(rules: &[Vec<String>]) -> AhoCorasick {
    let result: Vec<String> = rules.iter().filter_map(|v| v.first().cloned()).collect();

    AhoCorasick::new(&result).unwrap()
}
pub fn get_ip_trie<T: AsRef<str>>(target_ip_map: &HashMap<T, Vec<T>>) -> PrefixMap<Ipv4Net, usize> {
    let mut trie = PrefixMap::<Ipv4Net, usize>::new();
    for (i, (_key, value)) in target_ip_map.iter().enumerate() {
        for v in value {
            let r: Ipv4Net = v.as_ref().parse().unwrap();
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
struct Ipv4NetWrapper(pub Ipv4Net);
impl radix_trie::TrieKey for Ipv4NetWrapper {
    fn encode_bytes(&self) -> Vec<u8> {
        ipv4net_to_vec(&self.0)
    }
}
pub struct IpTrie2(Trie<Ipv4NetWrapper, usize>);
pub fn get_ip_trie2<T: AsRef<str>>(target_ip_map: &HashMap<T, Vec<T>>) -> IpTrie2 {
    let mut trie = Trie::<Ipv4NetWrapper, usize>::new();
    for (i, (_key, value)) in target_ip_map.iter().enumerate() {
        for v in value {
            let r: Ipv4Net = v.as_ref().parse().unwrap();
            trie.insert(Ipv4NetWrapper(r), i);
        }
    }
    IpTrie2(trie)
}
/// the function store ips in the trie with their target index of the map
pub fn get_ip6_trie<T: AsRef<str>>(
    target_ip_map: &HashMap<T, Vec<T>>,
) -> PrefixMap<Ipv6Net, usize> {
    let mut trie = PrefixMap::<Ipv6Net, usize>::new();
    for (i, (_key, value)) in target_ip_map.iter().enumerate() {
        for v in value {
            let r: Ipv6Net = v.as_ref().parse().unwrap();
            trie.insert(r, i);
        }
    }
    trie
}
/// the function store domains in the trie with their target index of the map
pub fn get_prefix_trie<T: AsRef<str>>(target_item_map: &HashMap<T, Vec<T>>) -> Trie<String, usize> {
    let mut trie = Trie::new();

    for (i, (_key, value)) in target_item_map.iter().enumerate() {
        for v in value {
            trie.insert(v.as_ref().to_string(), i);
        }
    }
    trie
}

/// the function store domain chars in the result trie in reversed order, and
/// with their target index of the map
pub fn get_suffix_trie<T: AsRef<str>>(
    target_suffix_map: &HashMap<T, Vec<T>>,
) -> Trie<String, usize> {
    let mut trie = Trie::new();

    for (i, (_key, value)) in target_suffix_map.iter().enumerate() {
        for v in value {
            let r: String = v.as_ref().chars().rev().collect();
            trie.insert(r, i);
        }
    }
    trie
}

/// basic hashmap matching
pub fn get_target<'a, K, V>(item_target_map: &'a HashMap<K, V>, item: &K) -> Option<&'a V>
where
    K: AsRef<str> + Eq + std::hash::Hash,
    V: AsRef<str> + Eq + std::hash::Hash,
{
    item_target_map.get(item)
}
pub fn check_suffix_dummy<'a, T>(
    target_suffix_map: &'a HashMap<T, Vec<T>>,
    domain: &str,
) -> Option<&'a T>
where
    T: AsRef<str> + Eq + std::hash::Hash,
{
    for (target, items) in target_suffix_map {
        for v in items {
            if domain.ends_with(v.as_ref()) {
                return Some(target);
            }
        }
    }
    None
}

/// the function matches suffix by reversing the domain
pub fn check_suffix_trie(trie: &Trie<String, usize>, domain: &str) -> Option<usize> {
    let sr: String = domain.chars().rev().collect();
    if let Some(subtree) = trie.get_ancestor(&sr) {
        subtree.value().cloned()
    } else {
        None
    }
}
/// unlike check_suffix_trie, this function matches prefix
pub fn check_prefix_trie(trie: &Trie<&str, usize>, domain: &str) -> Option<usize> {
    if let Some(subtree) = trie.get_ancestor(domain) {
        subtree.value().cloned()
    } else {
        None
    }
}
pub fn check_keyword_ac<'a, T: AsRef<str>>(
    target_keyword_ac_map: &'a HashMap<T, AhoCorasick>,
    domain: &str,
) -> Option<&'a str> {
    for (target, ac) in target_keyword_ac_map {
        if ac.is_match(domain) {
            return Some(target.as_ref());
        }
    }
    None
}

/// faster than ac, but requries an extra targets lookup vec by get_keywords_targets
pub fn check_keyword_ac2<'a>(
    keyword_ac: &AhoCorasick,
    domain: &str,
    targets: &'a [String],
) -> Option<&'a str> {
    if let Some(mat) = keyword_ac.find_iter(domain).next() {
        let keyword_index = mat.pattern();
        return Some(targets[keyword_index].as_str());
    }
    None
}

pub fn check_keyword_dummy<'a, T>(
    target_keyword_map: &'a HashMap<T, Vec<T>>,
    domain: &str,
) -> Option<&'a T>
where
    T: AsRef<str> + Eq + std::hash::Hash,
{
    for (target, items) in target_keyword_map {
        for v in items {
            if domain.contains(v.as_ref()) {
                return Some(target);
            }
        }
    }
    None
}

pub fn check_ip_trie2(trie: &IpTrie2, ip: Ipv4Addr) -> Option<usize> {
    let ipn = Ipv4NetWrapper(Ipv4Net::new(ip, 32).unwrap());
    if let Some(subtree) = trie.0.get_ancestor(&ipn) {
        subtree.value().cloned()
    } else {
        None
    }
}
pub fn check_ip_trie(trie: &PrefixMap<Ipv4Net, usize>, ip: Ipv4Addr) -> Option<usize> {
    trie.get_lpm(&Ipv4Net::new(ip, 32).unwrap()).map(|r| *r.1)
}
pub fn check_ip6_trie(trie: &PrefixMap<Ipv6Net, usize>, ip6: Ipv6Addr) -> Option<usize> {
    trie.get_lpm(&Ipv6Net::new(ip6, 32).unwrap()).map(|r| *r.1)
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
    let rule_map = parse_rules(&load_rules_from_file("test.yaml").unwrap());

    let dr = get_domain_rules(&rule_map).unwrap();
    println!("{:?}", dr.len());
    let suffix_rules = get_suffix_rules(&rule_map).unwrap();
    println!("{:?}", suffix_rules.len());
    let suffix_map = get_target_item_map(suffix_rules);

    let suffix_targets: Vec<&String> = suffix_map.keys().collect();

    println!("{:?}", suffix_targets);
    let trie = get_suffix_trie(&suffix_map);

    let keyword_rules = get_keyword_rules(&rule_map).unwrap();
    println!("{:?}", keyword_rules.len());
    let kmap = get_target_item_map(keyword_rules);
    let ac = get_keywords_ac(&kmap);
    let ac2 = get_keywords_ac2(keyword_rules);
    let ac2_targets = get_keywords_targets(keyword_rules);

    let ds = get_test_domains();
    for d in ds {
        let r = check_suffix_trie(&trie, d);
        println!("{:?}", r.map(|i| suffix_targets.get(i).unwrap()));
        let r = check_keyword_ac(&ac, d);
        println!("{:?}", r);
        let r = check_keyword_ac2(&ac2, d, &ac2_targets);
        println!("{:?}", r);
    }

    let ip_rules = get_ip_cidr_rules(&rule_map).unwrap();
    println!("{:?}", ip_rules.len());
    let ip_map = get_target_item_map(ip_rules);
    let ip_targets: Vec<_> = ip_map.keys().collect();
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
