pub use aho_corasick::AhoCorasick;
#[cfg(feature = "maxminddb")]
pub use maxminddb;
pub use prefix_trie::PrefixMap;
pub use radix_trie::{Trie, TrieCommon};
pub use serde_yaml_ng;

use ipnet::{Ipv4Net, Ipv6Net};
use std::collections::HashMap;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::{Deserialize, Serialize};
pub const DOMAIN: &str = "DOMAIN";
pub const DOMAIN_SUFFIX: &str = "DOMAIN-SUFFIX";
pub const DOMAIN_KEYWORD: &str = "DOMAIN-KEYWORD";
pub const IP_CIDR: &str = "IP-CIDR";
pub const IP_CIDR6: &str = "IP-CIDR6";
pub const PROCESS_NAME: &str = "PROCESS-NAME";
pub const GEOIP: &str = "GEOIP";
pub const MATCH: &str = "MATCH";

#[derive(Serialize, Deserialize, Debug)]
pub struct RuleSet {
    pub payload: Vec<String>,
}
#[derive(Debug)]
pub enum LoadYamlFileError {
    FileErr(std::io::Error),
    YamlErr(serde_yaml_ng::Error),
}
impl Display for LoadYamlFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadYamlFileError::FileErr(error) => write!(f, "{}", error),
            LoadYamlFileError::YamlErr(error) => write!(f, "{}", error),
        }
    }
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
    let ruleset = load_rule_set_from_str(&content)?;
    Ok(ruleset)
}
pub fn load_rule_set_from_str(s: &str) -> Result<RuleSet, serde_yaml_ng::Error> {
    let ruleset = serde_yaml_ng::from_str(s)?;
    Ok(ruleset)
}

/// init like let mut trie = Trie::new();
pub fn parse_rule_set_as_domain_suffix_trie(
    mut trie: Trie<String, usize>,
    payload: &[String],
    target_id: usize,
) {
    for v in payload.iter() {
        let mut r: String = v.chars().rev().collect();
        // RULESET 中 表示 suffix 的 字符串 有个 加号末尾（逆序后）
        r = r.trim_end_matches('+').to_string();
        trie.insert(r, target_id);
    }
}

/// init like let mut trie = PrefixMap::<Ipv4Net, usize>::new();
pub fn parse_rule_set_as_ip_cidr_trie(
    mut trie: PrefixMap<Ipv4Net, usize>,
    mut trie6: PrefixMap<Ipv6Net, usize>,
    payload: &[String],
    target_id: usize,
) {
    for v in payload.iter() {
        let r: Result<Ipv4Net, <Ipv4Net as std::str::FromStr>::Err> = v.parse();
        match r {
            Ok(r) => trie.insert(r, target_id),
            Err(_) => {
                let r: Ipv6Net = v.parse().unwrap();
                trie6.insert(r, target_id)
            }
        };
    }
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
    let s = std::fs::read_to_string(path)?;
    let rs = load_rules_from_str(&s)?;
    Ok(rs)
}
pub fn load_rules_from_str(s: &str) -> Result<RuleConfig, serde_yaml_ng::Error> {
    let rs = serde_yaml_ng::from_str(s)?;
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

pub fn merge_method_rules_map(
    map1: HashMap<String, Vec<Vec<String>>>,
    map2: HashMap<String, Vec<Vec<String>>>,
) -> HashMap<String, Vec<Vec<String>>> {
    let mut merged_map = map1;

    for (key, value) in map2 {
        merged_map.entry(key).or_default().extend(value);
    }

    merged_map
}

pub fn get_domain_rules(
    method_rules_map: &HashMap<String, Vec<Vec<String>>>,
) -> Option<&Vec<Vec<String>>> {
    method_rules_map.get(DOMAIN)
}
pub fn get_suffix_rules(
    method_rules_map: &HashMap<String, Vec<Vec<String>>>,
) -> Option<&Vec<Vec<String>>> {
    method_rules_map.get(DOMAIN_SUFFIX)
}
pub fn get_keyword_rules(
    method_rules_map: &HashMap<String, Vec<Vec<String>>>,
) -> Option<&Vec<Vec<String>>> {
    method_rules_map.get(DOMAIN_KEYWORD)
}
pub fn get_ip_cidr_rules(
    method_rules_map: &HashMap<String, Vec<Vec<String>>>,
) -> Option<&Vec<Vec<String>>> {
    method_rules_map.get(IP_CIDR)
}
pub fn get_ip6_cidr_rules(
    method_rules_map: &HashMap<String, Vec<Vec<String>>>,
) -> Option<&Vec<Vec<String>>> {
    method_rules_map.get(IP_CIDR6)
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

pub fn gen_keywords_ac(
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
pub fn gen_keywords_ac2(rules: &[Vec<String>]) -> AhoCorasick {
    let result: Vec<String> = rules.iter().filter_map(|v| v.first().cloned()).collect();

    AhoCorasick::new(&result).unwrap()
}
pub fn gen_ip_trie<T: AsRef<str>>(target_ip_map: &HashMap<T, Vec<T>>) -> PrefixMap<Ipv4Net, usize> {
    let mut trie = PrefixMap::<Ipv4Net, usize>::new();
    for (i, (_key, value)) in target_ip_map.iter().enumerate() {
        for v in value {
            let r: Ipv4Net = v.as_ref().parse().unwrap();
            trie.insert(r, i);
        }
    }
    trie
}
#[derive(PartialEq, Eq, Debug)]
struct Ipv4NetWrapper(pub Ipv4Net);
impl radix_trie::TrieKey for Ipv4NetWrapper {
    fn encode_bytes(&self) -> Vec<u8> {
        fn u32_to_bit_u8_vec(n: u32, len: u8) -> Vec<u8> {
            (32 - len..32u8).rev().map(|i| (n >> i) as u8).collect()
        }
        let ipnet = &self.0;
        u32_to_bit_u8_vec(
            u32::from_be_bytes(ipnet.network().octets()),
            ipnet.prefix_len(),
        )
    }
}

/// Trie struct for Ipv4Net using radix_trie::Trie, which is a bit slower than
/// prefix_trie::PrifixMap
pub struct IpTrie2(Trie<Ipv4NetWrapper, usize>);
pub fn gen_ip_trie2<T: AsRef<str>>(target_ip_map: &HashMap<T, Vec<T>>) -> IpTrie2 {
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
pub fn gen_ip6_trie<T: AsRef<str>>(
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
pub fn gen_prefix_trie<T: AsRef<str>>(target_item_map: &HashMap<T, Vec<T>>) -> Trie<String, usize> {
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
pub fn gen_suffix_trie<T: AsRef<str>>(
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
) -> Option<&'a String> {
    if let Some(mat) = keyword_ac.find_iter(domain).next() {
        let keyword_index = mat.pattern();
        return Some(&targets[keyword_index]);
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
fn test() {
    let rule_map = parse_rules(&load_rules_from_file("test.yaml").unwrap());

    let dr = get_domain_rules(&rule_map).unwrap();
    println!("{:?}", dr.len());
    let suffix_rules = get_suffix_rules(&rule_map).unwrap();
    println!("{:?}", suffix_rules.len());
    let suffix_map = get_target_item_map(suffix_rules);

    let suffix_targets: Vec<&String> = suffix_map.keys().collect();

    println!("{:?}", suffix_targets);
    let trie = gen_suffix_trie(&suffix_map);

    let keyword_rules = get_keyword_rules(&rule_map).unwrap();
    println!("{:?}", keyword_rules.len());
    let kmap = get_target_item_map(keyword_rules);
    let ac = gen_keywords_ac(&kmap);
    let ac2 = gen_keywords_ac2(keyword_rules);
    let ac2_targets = get_keywords_targets(keyword_rules);

    let ds = get_test_domains();
    for d in &ds {
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
    let it = gen_ip_trie(&ip_map);
    let it2 = gen_ip_trie2(&ip_map);

    let ips = get_test_ips();
    for ip in &ips {
        let r = check_ip_trie(&it, *ip);
        println!("{:?}", r.map(|i| ip_targets.get(i).unwrap()));
        let r = check_ip_trie2(&it2, *ip);
        println!("{:?}", r.map(|i| ip_targets.get(i).unwrap()));
    }

    let ip_rules = get_ip6_cidr_rules(&rule_map).unwrap();
    println!("{:?}", ip_rules.len());

    let cm = ClashRuleMatcher::from_clash_config_file("test.yaml").unwrap();
    for d in ds {
        let r = cm.check_domain(d);
        println!("{:?}", r);
    }
    for ip in ips {
        let r = cm.check_ip(std::net::IpAddr::V4(ip));
        println!("{:?}", r);
        // #[cfg(feature = "maxminddb")]
        // let r = cm.check_ip_country(std::net::IpAddr::V4(ip));
        // println!("{:?}", r);
    }
}
#[cfg(feature = "maxminddb")]
pub fn get_ip_iso_by_reader(ip: IpAddr, reader: &maxminddb::Reader<Vec<u8>>) -> &str {
    let r = reader.lookup(ip);
    let c: maxminddb::geoip2::Country = match r {
        Ok(c) => c,
        Err(_e) => {
            // warn!("look up maxminddb::Reader failed, {e}");
            return "";
        }
    };
    if let Some(c) = c.country {
        c.iso_code.unwrap_or_default()
    } else {
        ""
    }
}

#[derive(Debug)]
pub struct DomainKeywordMatcher {
    pub ac: AhoCorasick,
    pub targets: Vec<String>,
}
impl DomainKeywordMatcher {
    pub fn check(&self, domain: &str) -> Option<&String> {
        check_keyword_ac2(&self.ac, domain, &self.targets)
    }
}
#[derive(Debug)]
pub struct DomainSuffixMatcher {
    pub trie: Trie<String, usize>,
    pub targets: Vec<String>,
}
impl DomainSuffixMatcher {
    pub fn check(&self, domain: &str) -> Option<&String> {
        check_suffix_trie(&self.trie, domain).map(|i| self.targets.get(i).unwrap())
    }
}
#[derive(Debug)]
pub struct IpMatcher {
    pub trie: PrefixMap<Ipv4Net, usize>,
    pub targets: Vec<String>,
}
impl IpMatcher {
    pub fn check(&self, ip: Ipv4Addr) -> Option<&String> {
        check_ip_trie(&self.trie, ip).map(|i| self.targets.get(i).unwrap())
    }
}
#[derive(Debug)]
pub struct Ip6Matcher {
    pub trie: PrefixMap<Ipv6Net, usize>,
    pub targets: Vec<String>,
}
impl Ip6Matcher {
    pub fn check(&self, ip: Ipv6Addr) -> Option<&String> {
        check_ip6_trie(&self.trie, ip).map(|i| self.targets.get(i).unwrap())
    }
}

/// convenient struct for checking all rules.
/// init mmdb_reader using maxminddb::Reader::from_source
#[derive(Debug, Default)]
pub struct ClashRuleMatcher {
    pub domain_target_map: Option<HashMap<String, String>>,
    pub domain_keyword_matcher: Option<DomainKeywordMatcher>,
    pub domain_suffix_matcher: Option<DomainSuffixMatcher>,
    pub ip4_matcher: Option<IpMatcher>,
    pub ip6_matcher: Option<Ip6Matcher>,

    #[cfg(feature = "maxminddb")]
    pub mmdb_reader: Option<std::sync::Arc<maxminddb::Reader<Vec<u8>>>>,

    #[cfg(feature = "maxminddb")]
    pub country_target_map: Option<HashMap<String, String>>,
    /// left_rules stores rules that not handled by the ClashRuleMatcher
    pub left_rules: HashMap<String, Vec<Vec<String>>>,
}

impl ClashRuleMatcher {
    pub fn from_clash_config_str(cs: &str) -> Result<Self, serde_yaml_ng::Error> {
        let mut method_rules_map = parse_rules(&load_rules_from_str(cs)?);

        let mut s = Self::default();

        if let Some(v) = get_domain_rules(&method_rules_map) {
            s.domain_target_map = Some(get_item_target_map(v));
            method_rules_map.remove(DOMAIN);
        }
        #[cfg(feature = "maxminddb")]
        if let Some(v) = method_rules_map.get(GEOIP) {
            s.country_target_map = Some(get_item_target_map(v));
            method_rules_map.remove(GEOIP);
        }
        if let Some(v) = get_keyword_rules(&method_rules_map) {
            let map = get_target_item_map(v);
            let targets = map.keys().cloned().collect();
            let ac = gen_keywords_ac2(v);
            s.domain_keyword_matcher = Some(DomainKeywordMatcher { ac, targets });
            method_rules_map.remove(DOMAIN_KEYWORD);
        }
        if let Some(v) = get_suffix_rules(&method_rules_map) {
            let map = get_target_item_map(v);
            let targets = map.keys().cloned().collect();
            let trie = gen_suffix_trie(&map);
            s.domain_suffix_matcher = Some(DomainSuffixMatcher { trie, targets });
            method_rules_map.remove(DOMAIN_SUFFIX);
        }
        if let Some(v) = get_ip_cidr_rules(&method_rules_map) {
            let map = get_target_item_map(v);
            let targets = map.keys().cloned().collect();
            let trie = gen_ip_trie(&map);
            s.ip4_matcher = Some(IpMatcher { trie, targets });
            method_rules_map.remove(IP_CIDR);
        }
        if let Some(v) = get_ip6_cidr_rules(&method_rules_map) {
            let map = get_target_item_map(v);
            let targets = map.keys().cloned().collect();
            let trie = gen_ip6_trie(&map);
            s.ip6_matcher = Some(Ip6Matcher { trie, targets });
            method_rules_map.remove(IP_CIDR6);
        }
        s.left_rules = method_rules_map;

        Ok(s)
    }
    pub fn from_clash_config_file<P: AsRef<Path>>(path: P) -> Result<Self, LoadYamlFileError> {
        let s = std::fs::read_to_string(path)?;
        let s = Self::from_clash_config_str(&s)?;
        Ok(s)
    }

    pub fn check_ip4(&self, ip: Ipv4Addr) -> Option<&String> {
        if let Some(m) = &self.ip4_matcher {
            m.check(ip)
        } else {
            None
        }
    }
    pub fn check_ip6(&self, ip: Ipv6Addr) -> Option<&String> {
        if let Some(m) = &self.ip6_matcher {
            m.check(ip)
        } else {
            None
        }
    }
    pub fn check_ip(&self, ip: std::net::IpAddr) -> Option<&String> {
        match ip {
            std::net::IpAddr::V4(ipv4_addr) => self.check_ip4(ipv4_addr),
            std::net::IpAddr::V6(ipv6_addr) => self.check_ip6(ipv6_addr),
        }
    }
    #[cfg(feature = "maxminddb")]
    pub fn check_ip_country_iso(&self, ip: std::net::IpAddr) -> &str {
        if let Some(m) = &self.mmdb_reader {
            get_ip_iso_by_reader(ip, m)
        } else {
            ""
        }
    }
    #[cfg(feature = "maxminddb")]
    pub fn check_ip_country(&self, ip: std::net::IpAddr) -> Option<&String> {
        if let Some(m) = &self.country_target_map {
            let c = self.check_ip_country_iso(ip);
            m.get(c)
        } else {
            None
        }
    }

    pub fn check_domain(&self, domain: &str) -> Option<&String> {
        if let Some(m) = &self.domain_target_map {
            let r = m.get(domain);
            if r.is_some() {
                return r;
            }
        }
        if let Some(m) = &self.domain_suffix_matcher {
            let r = m.check(domain);
            if r.is_some() {
                return r;
            }
        }
        if let Some(m) = &self.domain_keyword_matcher {
            let r = m.check(domain);
            if r.is_some() {
                return r;
            }
        }
        None
    }
}
