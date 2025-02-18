pub use aho_corasick::AhoCorasick;
#[cfg(feature = "maxminddb")]
pub use maxminddb;
pub use prefix_trie::PrefixMap;
pub use radix_trie::{Trie, TrieCommon};
#[cfg(feature = "rusqlite")]
pub use rusqlite;

#[cfg(feature = "serde_yaml_ng")]
pub use serde_yaml_ng;

#[cfg(feature = "rusqlite")]
pub mod sql;

use ipnet::{Ipv4Net, Ipv6Net};
use std::collections::HashMap;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::ParseIntError;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub const DOMAIN: &str = "DOMAIN";
pub const DOMAIN_SUFFIX: &str = "DOMAIN-SUFFIX";
pub const DOMAIN_KEYWORD: &str = "DOMAIN-KEYWORD";
pub const DOMAIN_REGEX: &str = "DOMAIN-REGEX";
pub const IP_CIDR: &str = "IP-CIDR";
pub const IP_CIDR6: &str = "IP-CIDR6";
pub const PROCESS_NAME: &str = "PROCESS-NAME";
pub const DST_PORT: &str = "DST-PORT";
pub const GEOIP: &str = "GEOIP";
pub const NETWORK: &str = "NETWORK";
pub const AND: &str = "AND";
pub const OR: &str = "OR";
pub const NOT: &str = "NOT";
pub const MATCH: &str = "MATCH";

/// all supported rules
pub const RULE_TYPES: &[&str] = &[
    DOMAIN,
    DOMAIN_KEYWORD,
    DOMAIN_SUFFIX,
    DOMAIN_REGEX,
    IP_CIDR,
    IP_CIDR6,
    PROCESS_NAME,
    DST_PORT,
    GEOIP,
    NETWORK,
    MATCH,
    AND,
    OR,
    NOT,
];

/// to lowercase and - to _
pub fn to_sql_table_name(rule_name: &str) -> String {
    rule_name.replace("-", "_").to_lowercase()
}
/// to uppercase and _ to -
pub fn to_clash_rule_name(rule_name: &str) -> String {
    rule_name.replace("_", "-").to_uppercase()
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RuleSet {
    pub payload: Vec<String>,
}
pub enum RuleSetType {
    Domain,
    Ipcidr,
    Classical,
}
#[derive(Debug)]
pub enum LoadYamlFileError {
    FileErr(std::io::Error),
    #[cfg(feature = "serde_yaml_ng")]
    YamlErr(serde_yaml_ng::Error),
}
impl Display for LoadYamlFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadYamlFileError::FileErr(error) => write!(f, "{}", error),
            #[cfg(feature = "serde_yaml_ng")]
            LoadYamlFileError::YamlErr(error) => write!(f, "{}", error),
        }
    }
}

impl From<std::io::Error> for LoadYamlFileError {
    fn from(err: std::io::Error) -> Self {
        LoadYamlFileError::FileErr(err)
    }
}

#[cfg(feature = "serde_yaml_ng")]
impl From<serde_yaml_ng::Error> for LoadYamlFileError {
    fn from(err: serde_yaml_ng::Error) -> Self {
        LoadYamlFileError::YamlErr(err)
    }
}

#[cfg(feature = "serde_yaml_ng")]
pub fn load_rule_set_from_file<P: AsRef<Path>>(path: P) -> Result<RuleSet, LoadYamlFileError> {
    let content = std::fs::read_to_string(path)?;
    let ruleset = load_rule_set_from_str(&content)?;
    Ok(ruleset)
}
#[cfg(feature = "serde_yaml_ng")]
pub fn load_rule_set_from_str(s: &str) -> Result<RuleSet, serde_yaml_ng::Error> {
    let ruleset = serde_yaml_ng::from_str(s)?;
    Ok(ruleset)
}

/// init like: let mut trie = Trie::new();
///
/// will add items in payload that start with '+' which marks as DOMAIN-SUFFIX
pub fn parse_rule_set_as_domain_suffix_trie(
    trie: &mut Trie<String, usize>,
    payload: &mut Vec<String>,
    target_id: usize,
) {
    payload.retain(|x| {
        let ok = x.starts_with('+');
        if ok {
            let mut r: String = x.chars().rev().collect();
            r = r.trim_end_matches('+').to_string();
            trie.insert(r, target_id);
        }

        !ok
    });
}

/// init like let mut trie = PrefixMap::<Ipv4Net, usize>::new();
pub fn parse_rule_set_as_ip_cidr_trie(
    trie: &mut PrefixMap<Ipv4Net, usize>,
    trie6: &mut PrefixMap<Ipv6Net, usize>,
    payload: &[String],
    target_id_for_v4: usize,
    target_id_for_v6: usize,
) {
    for v in payload.iter() {
        let r: Result<Ipv4Net, <Ipv4Net as std::str::FromStr>::Err> = v.parse();
        match r {
            Ok(r) => trie.insert(r, target_id_for_v4),
            Err(_) => {
                let r: Ipv6Net = v.parse().unwrap();
                trie6.insert(r, target_id_for_v6)
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

/// Contains the clash rule lines
#[derive(Serialize, Deserialize, Debug)]
pub struct RuleConfig {
    pub rules: Vec<String>,
}
#[cfg(feature = "serde_yaml_ng")]
pub fn load_rules_from_file<P: AsRef<Path>>(path: P) -> Result<RuleConfig, LoadYamlFileError> {
    let s = std::fs::read_to_string(path)?;
    let rs = load_rules_from_str(&s)?;
    Ok(rs)
}
#[cfg(feature = "serde_yaml_ng")]
pub fn load_rules_from_str(s: &str) -> Result<RuleConfig, serde_yaml_ng::Error> {
    let rs = serde_yaml_ng::from_str(s)?;
    Ok(rs)
}

/// parse a single clahs rule line by spliting with ',', the ',' splitted items is pushed in the inner Vec
pub fn parse_line(rule: &str) -> Option<(&str, Vec<String>)> {
    let mut parts = rule.split(',');
    if let Some(key) = parts.next() {
        let values: Vec<String> = parts.map(|part| part.to_string()).collect();
        return Some((key, values));
    }
    None
}

/// parse clash rules into METHOD-rules hashmap, the ',' splitted items is pushed in the inner Vec
pub fn parse_rules(rc: &RuleConfig) -> HashMap<String, Vec<Vec<String>>> {
    // rule, items
    let mut hashmap: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    for rule in &rc.rules {
        if let Some((key, values)) = parse_line(rule) {
            hashmap.entry(key.to_string()).or_default().push(values);
        }
    }
    hashmap
}

/// merge two into a new one
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
pub fn get_test_ips() -> Vec<(Ipv4Addr, Option<&'static str>)> {
    vec![
        (Ipv4Addr::new(1, 2, 3, 4), None),
        (Ipv4Addr::new(2, 2, 3, 4), None),
        (Ipv4Addr::new(3, 2, 3, 4), None),
        (Ipv4Addr::new(15, 207, 213, 128), Some("Netflix")),
    ]
}
/// suffix target, keyword target
#[cfg(test)]
pub fn get_test_domains() -> Vec<(&'static str, Option<&'static str>, Option<&'static str>)> {
    vec![
        ("www.google.com", Some("Google"), Some("Google")),
        ("jdj.reddit.com", Some("Proxies"), None),
        ("hdjd.baidu.com", Some("🎯Direct"), Some("🎯Direct")),
        ("hshsh.djdjdj.d", None, None),
    ]
}
/// cargo test test_algorithms -- --nocapture
#[cfg(feature = "serde_yaml_ng")]
#[test]
fn test_algorithms() {
    let rule_map = parse_rules(&load_rules_from_file("test.yaml").unwrap());

    let dr = rule_map.get(DOMAIN).unwrap();
    println!("{:?}", dr.len());
    let suffix_rules = rule_map.get(DOMAIN_SUFFIX).unwrap();
    println!("{:?}", suffix_rules.len());
    let suffix_map = get_target_item_map(suffix_rules);

    let suffix_targets: Vec<&String> = suffix_map.keys().collect();

    println!("{:?}", suffix_targets);
    let trie = gen_suffix_trie(&suffix_map);

    let keyword_rules = rule_map.get(DOMAIN_KEYWORD).unwrap();
    println!("{:?}", keyword_rules.len());
    let kmap = get_target_item_map(keyword_rules);
    let ac = gen_keywords_ac(&kmap);
    let ac2 = gen_keywords_ac2(keyword_rules);
    let ac2_targets = get_keywords_targets(keyword_rules);

    let ds = get_test_domains();
    for (d, st, kt) in &ds {
        println!("{:?}", d);
        let r = check_suffix_trie(&trie, d);
        let r = r.map(|i| suffix_targets.get(i).unwrap().as_str());
        println!("{:?}", r);
        assert_eq!(r, *st);
        let r = check_keyword_ac(&ac, d);
        println!("{:?}", r);
        assert_eq!(r, *kt);
        let r = check_keyword_ac2(&ac2, d, &ac2_targets).map(|s| s.as_str());
        println!("{:?}", r);
        assert_eq!(r, *kt);
    }

    let ip_rules = rule_map.get(IP_CIDR).unwrap();
    println!("{:?}", ip_rules.len());
    let ip_map = get_target_item_map(ip_rules);
    let ip_targets: Vec<_> = ip_map.keys().collect();
    let it = gen_ip_trie(&ip_map);
    let it2 = gen_ip_trie2(&ip_map);

    let ips = get_test_ips();
    for (ip, t) in &ips {
        println!("{:?}", ip);
        let r = check_ip_trie(&it, *ip);
        let r = r.map(|i| ip_targets.get(i).unwrap().as_str());
        println!("{:?}", r);
        assert_eq!(r, *t);
        let r = check_ip_trie2(&it2, *ip);
        let r = r.map(|i| ip_targets.get(i).unwrap().as_str());
        println!("{:?}", r);
        assert_eq!(r, *t);
    }

    let ip_rules = rule_map.get(IP_CIDR6).unwrap();
    println!("{:?}", ip_rules.len());

    let cm = ClashRuleMatcher::from_clash_config_file("test.yaml").unwrap();
    for (d, st, kt) in ds {
        let r = cm.check_domain(d).map(|s| s.as_str());
        println!("{:?}", r);
        assert!(r.eq(&st) || r.eq(&kt))
    }
    for (ip, t) in ips {
        let r = cm.check_ip(std::net::IpAddr::V4(ip)).map(|s| s.as_str());
        println!("{:?}", r);
        assert_eq!(r, t);
        // #[cfg(feature = "maxminddb")]
        // let r = cm.check_ip_country(std::net::IpAddr::V4(ip));
        // println!("{:?}", r);
    }
}
#[cfg(feature = "maxminddb")]
/// return the iso 3166 code, see <https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes>
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

#[derive(Debug, Default)]
pub struct DomainFullMatcher {
    // store usize instead of using HashMap<String, String>,
    // to save memory
    pub map: HashMap<String, usize>,
    pub targets: Vec<String>,
}
impl DomainFullMatcher {
    pub fn check(&self, domain: &str) -> Option<&String> {
        self.map.get(domain).and_then(|&i| self.targets.get(i))
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
impl Default for DomainSuffixMatcher {
    fn default() -> Self {
        Self {
            trie: Trie::new(),
            targets: vec![],
        }
    }
}
impl DomainSuffixMatcher {
    pub fn check(&self, domain: &str) -> Option<&String> {
        check_suffix_trie(&self.trie, domain).map(|i| self.targets.get(i).unwrap())
    }
}
#[derive(Debug, Default)]
pub struct IpMatcher {
    pub trie: PrefixMap<Ipv4Net, usize>,
    pub targets: Vec<String>,
}
impl IpMatcher {
    pub fn check(&self, ip: Ipv4Addr) -> Option<&String> {
        check_ip_trie(&self.trie, ip).map(|i| self.targets.get(i).unwrap())
    }
}
#[derive(Debug, Default)]
pub struct Ip6Matcher {
    pub trie: PrefixMap<Ipv6Net, usize>,
    pub targets: Vec<String>,
}
impl Ip6Matcher {
    pub fn check(&self, ip: Ipv6Addr) -> Option<&String> {
        check_ip6_trie(&self.trie, ip).map(|i| self.targets.get(i).unwrap())
    }
}

/// Convenient struct for checking all rules.
/// init mmdb_reader using maxminddb::Reader::from_source
#[derive(Debug, Default)]
pub struct ClashRuleMatcher {
    // pub domain_target_map: Option<HashMap<String, String>>,
    pub domain_full_matcher: Option<DomainFullMatcher>,
    pub domain_keyword_matcher: Option<DomainKeywordMatcher>,
    pub domain_suffix_matcher: Option<DomainSuffixMatcher>,
    pub domain_regex_set: Option<HashMap<String, regex::RegexSet>>,
    pub ip4_matcher: Option<IpMatcher>,
    pub ip6_matcher: Option<Ip6Matcher>,

    /// for GEOIP
    #[cfg(feature = "maxminddb")]
    pub mmdb_reader: Option<std::sync::Arc<maxminddb::Reader<Vec<u8>>>>,

    /// for GEOIP
    #[cfg(feature = "maxminddb")]
    pub country_target_map: Option<HashMap<String, String>>,

    /// stores un-optimized left rules, which are AND,OR,NOT,PROCESS-NAME,
    /// DST-PORT, NETWORK,MATCH
    ///
    /// (rule, target)
    pub rules: Vec<(Rule, String)>,
}

impl ClashRuleMatcher {
    pub fn from_hashmap(
        mut method_rules_map: HashMap<String, Vec<Vec<String>>>,
    ) -> Result<Self, ParseRuleError> {
        let mut s = Self::default();

        if let Some(v) = method_rules_map.get(DOMAIN) {
            let domain_target_map = get_item_target_map(v);
            let vs: Vec<String> = domain_target_map.values().map(|s| s.to_string()).collect();
            let m = domain_target_map
                .into_iter()
                .map(|(k, v)| (k, vs.iter().position(|x| x.eq(&v)).unwrap()))
                .collect();
            s.domain_full_matcher = Some(DomainFullMatcher {
                map: m,
                targets: vs,
            });
            method_rules_map.remove(DOMAIN);
        }
        #[cfg(feature = "maxminddb")]
        if let Some(v) = method_rules_map.get(GEOIP) {
            s.country_target_map = Some(get_item_target_map(v));
            method_rules_map.remove(GEOIP);
        }
        if let Some(v) = method_rules_map.get(DOMAIN_REGEX) {
            let map = get_target_item_map(v);
            s.domain_regex_set = Some(
                map.into_iter()
                    .map(|(t, r)| (t, regex::RegexSet::new(r).unwrap()))
                    .collect(),
            );
            method_rules_map.remove(DOMAIN_REGEX);
        }
        if let Some(v) = method_rules_map.get(DOMAIN_KEYWORD) {
            let map = get_target_item_map(v);
            let targets = map.keys().cloned().collect();
            let ac = gen_keywords_ac2(v);
            s.domain_keyword_matcher = Some(DomainKeywordMatcher { ac, targets });
            method_rules_map.remove(DOMAIN_KEYWORD);
        }
        if let Some(v) = method_rules_map.get(DOMAIN_SUFFIX) {
            let map = get_target_item_map(v);
            let targets = map.keys().cloned().collect();
            let trie = gen_suffix_trie(&map);
            s.domain_suffix_matcher = Some(DomainSuffixMatcher { trie, targets });
            method_rules_map.remove(DOMAIN_SUFFIX);
        }
        if let Some(v) = method_rules_map.get(IP_CIDR) {
            let map = get_target_item_map(v);
            let targets = map.keys().cloned().collect();
            let trie = gen_ip_trie(&map);
            s.ip4_matcher = Some(IpMatcher { trie, targets });
            method_rules_map.remove(IP_CIDR);
        }
        if let Some(v) = method_rules_map.get(IP_CIDR6) {
            let map = get_target_item_map(v);
            let targets = map.keys().cloned().collect();
            let trie = gen_ip6_trie(&map);
            s.ip6_matcher = Some(Ip6Matcher { trie, targets });
            method_rules_map.remove(IP_CIDR6);
        }
        let mt = method_rules_map.remove(MATCH);

        for (rt, item) in method_rules_map {
            for mut content in item {
                let target = if content.len() > 1 {
                    content.remove(1)
                } else {
                    content.pop().unwrap()
                };
                content.insert(0, rt.clone());
                let rs = content.join(",");
                let r = parse_rule(&rs)?;
                s.rules.push((r, target));
            }
        }

        // put MATCH at the end, make sure only shows up once
        if let Some(mut t) = mt {
            if !t.is_empty() {
                let mut t = t.remove(0);
                if !t.is_empty() {
                    let t = t.remove(0);
                    s.rules.push((Rule::Match, t));
                }
            }
        }

        Ok(s)
    }
    pub fn from_clash_rules(rc: &RuleConfig) -> Result<Self, ParseRuleError> {
        let method_rules_map = parse_rules(rc);

        Self::from_hashmap(method_rules_map)
    }
    #[cfg(feature = "serde_yaml_ng")]
    pub fn from_clash_config_str(cs: &str) -> Result<Self, ParseRuleError> {
        let rc = load_rules_from_str(cs)?;
        Self::from_clash_rules(&rc)
    }
    #[cfg(feature = "serde_yaml_ng")]
    pub fn from_clash_config_file<P: AsRef<Path>>(path: P) -> Result<Self, ParseRuleError> {
        let s = std::fs::read_to_string(path)?;
        Self::from_clash_config_str(&s)
    }

    /// RuleSetType must be Ipcidr or Domain, can't be Classical, as
    /// classical rules can't be merged after the ClashRuleMatcher was created.
    ///
    /// If you want to merge classical ruleset, merge it as HashMap and
    /// use the merged HashMap to create the ClashRuleMatcher.
    pub fn append_rule_set(&mut self, t: RuleSetType, mut rs: RuleSet, target: &str) {
        match t {
            RuleSetType::Domain => {
                let mut matcher = self.domain_suffix_matcher.take().unwrap_or_default();
                let target_id = matcher.targets.iter().position(|x| x.eq(target)).unwrap_or_else(|| {
                    let l = matcher.targets.len();
                    matcher.targets.push(target.to_string());
                    l
                });

                parse_rule_set_as_domain_suffix_trie(&mut matcher.trie, &mut rs.payload, target_id);
                self.domain_suffix_matcher = Some(matcher);
                if !rs.payload.is_empty(){
                    let mut m = self.domain_full_matcher.take().unwrap_or_default();
                    let target_id = m.targets.iter().position(|x| x.eq(target)).unwrap_or_else(|| {
                        let l = m.targets.len();
                        m.targets.push(target.to_string());
                        l
                    });
                    rs.payload.iter().for_each(|d| {
                        m.map.insert(d.to_string(), target_id);
                    });

                    self.domain_full_matcher= Some(m);

                }
            },
            RuleSetType::Ipcidr => {
                let mut matcher4 = self.ip4_matcher.take().unwrap_or_default();
                let mut matcher6 = self.ip6_matcher.take().unwrap_or_default();
                let target_id4 = matcher4.targets.iter().position(|x| x.eq(target)).unwrap_or_else(|| {
                    let l = matcher4.targets.len();
                    matcher4.targets.push(target.to_string());
                    l
                });
                let target_id6 = matcher6.targets.iter().position(|x| x.eq(target)).unwrap_or_else(|| {
                    let l = matcher6.targets.len();
                    matcher6.targets.push(target.to_string());
                    l
                });

                parse_rule_set_as_ip_cidr_trie(&mut matcher4.trie, &mut matcher6.trie, &rs.payload, target_id4, target_id6);

                    self.ip4_matcher= Some(matcher4);
                    self.ip6_matcher= Some(matcher6);

            },
            RuleSetType::Classical => panic!("can not merge classical ruleset afterwards. Merge as HashMap before creating ClashRuleMatcher."),
        }
    }

    /// returns the target if matched
    pub fn check_ip4(&self, ip: Ipv4Addr) -> Option<&String> {
        if let Some(m) = &self.ip4_matcher {
            m.check(ip)
        } else {
            None
        }
    }
    /// returns the target if matched
    pub fn check_ip6(&self, ip: Ipv6Addr) -> Option<&String> {
        if let Some(m) = &self.ip6_matcher {
            m.check(ip)
        } else {
            None
        }
    }
    /// returns the target if matched
    pub fn check_ip(&self, ip: std::net::IpAddr) -> Option<&String> {
        match ip {
            std::net::IpAddr::V4(ipv4_addr) => self.check_ip4(ipv4_addr),
            std::net::IpAddr::V6(ipv6_addr) => self.check_ip6(ipv6_addr),
        }
    }

    /// returns the iso of the ip
    #[cfg(feature = "maxminddb")]
    pub fn check_ip_country_iso(&self, ip: std::net::IpAddr) -> &str {
        if let Some(m) = &self.mmdb_reader {
            get_ip_iso_by_reader(ip, m)
        } else {
            ""
        }
    }
    /// returns the target if matched
    #[cfg(feature = "maxminddb")]
    pub fn check_ip_country(&self, ip: std::net::IpAddr) -> Option<&String> {
        if let Some(m) = &self.country_target_map {
            let c = self.check_ip_country_iso(ip);
            m.get(c)
        } else {
            None
        }
    }

    /// returns the target if matched
    pub fn check_domain(&self, domain: &str) -> Option<&String> {
        if let Some(m) = &self.domain_full_matcher {
            let r = m.check(domain);
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
        if let Some(m) = &self.domain_regex_set {
            for (t, r) in m {
                if r.is_match(domain) {
                    return Some(t);
                }
            }
        }
        None
    }
    /// returns the target if matched
    pub fn matches(&self, input: &RuleInput) -> Option<&String> {
        let dt = input.domain.as_ref().and_then(|d| self.check_domain(d));
        if dt.is_some() {
            return dt;
        }
        let it = input.ip.and_then(|d| self.check_ip(d));
        if it.is_some() {
            return it;
        }
        #[cfg(feature = "maxminddb")]
        {
            let it = input.ip.and_then(|d| self.check_ip_country(d));
            if it.is_some() {
                return it;
            }
        }
        for r in self.rules.iter() {
            if r.0.matches(input) {
                return Some(&r.1);
            }
        }
        None
    }
}

/// All supported clash rules
#[derive(Debug)]
pub enum Rule {
    And(Vec<Rule>),
    Or(Vec<Rule>),
    Not(Box<Rule>),
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(regex::Regex),
    IpCidr(Ipv4Net),
    IpCidr6(Ipv6Net),
    GeoIp(String),
    Network(String),
    DstPort(u16),
    ProcessName(String),
    Match,
    Other(String, String),
}

/// the struct stores all possible rule inputs for checking
#[derive(Default, Debug)]
pub struct RuleInput {
    pub domain: Option<String>,
    pub process_name: Option<String>,
    pub network: Option<String>,
    pub ip: Option<IpAddr>,
    pub dst_port: Option<u16>,

    /// for geoip (as different mmdb can give different results)
    #[cfg(feature = "maxminddb")]
    pub mmdb_reader: Option<std::sync::Arc<maxminddb::Reader<Vec<u8>>>>,
}

impl Rule {
    /// from normal rule. For logic rules use parse_rule
    pub fn from_content_type(r: &str, rule_type: &str) -> Result<Rule, ParseRuleError> {
        Ok(match rule_type {
            DOMAIN => Rule::Domain(r.to_string()),
            GEOIP => Rule::GeoIp(r.to_string()),
            MATCH => Rule::Match,
            PROCESS_NAME => Rule::ProcessName(r.to_string()),
            NETWORK => Rule::Network(r.to_string()),
            DST_PORT => Rule::DstPort(r.parse()?),
            DOMAIN_SUFFIX => Rule::DomainSuffix(r.to_string()),
            DOMAIN_KEYWORD => Rule::DomainKeyword(r.to_string()),
            DOMAIN_REGEX => Rule::DomainRegex(regex::Regex::new(r)?),
            IP_CIDR6 => {
                let mut r = r.to_string();
                if let Some(pos) = r.find(',') {
                    r.truncate(pos);
                }
                let r: Ipv6Net = r.parse()?;
                Rule::IpCidr6(r)
            }
            IP_CIDR => {
                let mut r = r.to_string();
                if let Some(pos) = r.find(',') {
                    r.truncate(pos);
                }
                let r: Ipv4Net = r.parse()?;
                Rule::IpCidr(r)
            }
            _ => Rule::Other(rule_type.to_string(), r.to_string()),
        })
    }
    pub fn matches(&self, input: &RuleInput) -> bool {
        match self {
            Rule::Match => true,
            Rule::And(rules) => {
                for r in rules {
                    if !r.matches(input) {
                        return false;
                    }
                }
                true
            }
            Rule::Or(rules) => {
                for r in rules {
                    if r.matches(input) {
                        return true;
                    }
                }
                false
            }
            Rule::Not(rule) => !rule.matches(input),

            Rule::ProcessName(p) => input
                .process_name
                .as_ref()
                .is_some_and(|real_p| real_p.eq(p)),
            Rule::Network(n) => input.network.as_ref().is_some_and(|d| d.eq(n)),
            Rule::Domain(domain) => input.domain.as_ref().is_some_and(|d| d.eq(domain)),
            Rule::DomainRegex(r) => input.domain.as_ref().is_some_and(|d| r.is_match(d)),
            Rule::DomainSuffix(suffix) => {
                input.domain.as_ref().is_some_and(|d| d.ends_with(suffix))
            }
            Rule::DomainKeyword(k) => input.domain.as_ref().is_some_and(|d| d.contains(k)),
            Rule::IpCidr6(n) => input.ip.as_ref().is_some_and(|ip| {
                if let IpAddr::V6(i) = ip {
                    n.contains(i)
                } else {
                    false
                }
            }),
            Rule::IpCidr(n) => input.ip.as_ref().is_some_and(|ip| {
                if let IpAddr::V4(i) = ip {
                    n.contains(i)
                } else {
                    false
                }
            }),
            #[cfg(feature = "maxminddb")]
            Rule::GeoIp(region) => input.ip.is_some_and(|ip| {
                if let Some(m) = &input.mmdb_reader {
                    let iso = get_ip_iso_by_reader(ip, m);
                    iso.eq(region)
                } else {
                    false
                }
            }),
            Rule::DstPort(d) => input.dst_port.is_some_and(|rd| rd == *d),
            _ => false,
        }
    }
}

use thiserror::Error;

// The parsing error type of the crate
#[derive(Error, Debug)]
pub enum ParseRuleError {
    #[cfg(feature = "serde_yaml_ng")]
    #[error("parse yaml err")]
    ParseYaml(#[from] serde_yaml_ng::Error),
    #[error("read file err")]
    FileErr(#[from] std::io::Error),

    #[error("no comma")]
    NoComma,
    #[error("not wrapped with ()")]
    NotWrappedBracket,
    #[error("no sub rule")]
    NoSubrule,
    #[error("no bracket")]
    NoBracket,
    #[error("bracket should follow comma")]
    E5,
    #[error("regex error")]
    Regex(#[from] regex::Error),
    #[error("parse ipcidr err")]
    ParseIpnet(#[from] ipnet::AddrParseError),
    #[error("parse dst port err")]
    ParseNum(#[from] ParseIntError),
}

fn process_rules(rules: Vec<String>) -> Result<Vec<Rule>, ParseRuleError> {
    rules.into_iter().map(|s| parse_rule(&s)).collect()
}

///parse a clash rule line without target, mainly for logic rules.
///
///eg: DOMAIN-KEYWORD,bili
///eg: AND,((DOMAIN-KEYWORD,bili),(DOMAIN-REGEX,(?i)pcdn|mcdn))
pub fn parse_rule(input: &str) -> Result<Rule, ParseRuleError> {
    if input == MATCH {
        return Ok(Rule::Match);
    }
    let (rt, r) = input.split_once(",").ok_or(ParseRuleError::NoComma)?;

    if rt.eq(AND) || rt.eq(OR) || rt.eq(NOT) {
        if !(r.starts_with('(') && r.ends_with(')')) {
            return Err(ParseRuleError::NotWrappedBracket);
        }
        let r = &r[1..r.len() - 1];
        let subrules: Vec<_> = extract_sub_rules_from(r)?;
        let mut subrules = process_rules(subrules)?;
        let r = match rt {
            AND => Rule::And(subrules),
            OR => Rule::Or(subrules),
            NOT => {
                let b = subrules.pop().ok_or(ParseRuleError::NoSubrule)?;
                Rule::Not(Box::new(b))
            }
            _ => unreachable!(""),
        };
        Ok(r)
    } else {
        Rule::from_content_type(r, rt)
    }
}

/// input eg: (DOMAIN-KEYWORD,bili),(DOMAIN-REGEX,(?i)pcdn|mcdn)
///
/// input eg: (AND,((DOMAIN,1),(DOMAIN,2))),(DOMAIN-REGEX,(?i)pcdn|mcdn)
fn extract_sub_rules_from(input: &str) -> Result<Vec<String>, ParseRuleError> {
    if input.starts_with('(') {
        let mut v = vec![];
        let mut lbi = 0;
        loop {
            let rbi = find_matching_bracket(input, lbi).ok_or(ParseRuleError::NoBracket)?;
            let s = &input[lbi + 1..rbi];
            v.push(s.trim().to_string());
            if rbi + 1 == input.len() {
                break;
            }

            let commap = input[rbi + 1..].find(',').ok_or(ParseRuleError::NoComma)?;
            let bp = input[rbi + 1..].find('(').unwrap();
            if commap >= bp {
                return Err(ParseRuleError::E5);
            }

            lbi = bp + rbi + 1;
        }
        Ok(v)
    } else {
        let r = &input[1..input.len() - 1];
        Ok(vec![r.trim().to_string()])
    }
}

fn find_matching_bracket(text: &str, left_bracket_index: usize) -> Option<usize> {
    let mut stack = 0;
    for (i, c) in text[left_bracket_index..].char_indices() {
        match c {
            '(' => stack += 1,
            ')' => {
                stack -= 1;
                if stack == 0 {
                    return Some(left_bracket_index + i);
                }
            }
            _ => {}
        }
    }
    None
}

/// cargo test test_logic -- --nocapture
#[test]
fn test_logic() {
    let rule_str = "OR,((DOMAIN-KEYWORD,bili),(DOMAIN-REGEX,(?i)pcdn|mcdn))";
    let rule0 = parse_rule(rule_str).unwrap();
    println!("{:#?}", rule0);
    let rule_str = "AND,((DOMAIN-KEYWORD,bili),(DOMAIN-REGEX,(?i)pcdn|mcdn))";
    let rule = parse_rule(rule_str).unwrap();
    println!("{:#?}", rule);
    assert!(rule0.matches(&RuleInput {
        domain: Some("pcdbili.com".to_string()),
        ..Default::default()
    }));
    assert!(!rule.matches(&RuleInput {
        domain: Some("pcdbili.com".to_string()),
        ..Default::default()
    }));
    assert!(rule.matches(&RuleInput {
        domain: Some("pcdn.bili.com".to_string()),
        ..Default::default()
    }));
    let rule_str = "AND,((OR,((DOMAIN-KEYWORD,bili),(DOMAIN,0))),(DOMAIN-REGEX,(?i)pcdn|mcdn))";
    let rule = parse_rule(rule_str);
    println!("{:#?}", rule);
}
