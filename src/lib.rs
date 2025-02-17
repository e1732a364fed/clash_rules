pub use aho_corasick::AhoCorasick;
#[cfg(feature = "maxminddb")]
pub use maxminddb;
pub use prefix_trie::PrefixMap;
pub use radix_trie::{Trie, TrieCommon};
#[cfg(feature = "rusqlite")]
pub use rusqlite;

#[cfg(feature = "serde_yaml_ng")]
pub use serde_yaml_ng;

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
///
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
pub fn to_sql_table_name(input: &str) -> String {
    input.replace("-", "_").to_lowercase()
}
pub fn to_clash_rule_name(input: &str) -> String {
    input.replace("_", "-").to_uppercase()
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RuleSet {
    pub payload: Vec<String>,
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
#[cfg(feature = "serde_yaml_ng")]
#[test]
fn test() {
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
    for d in &ds {
        let r = check_suffix_trie(&trie, d);
        println!("{:?}", r.map(|i| suffix_targets.get(i).unwrap()));
        let r = check_keyword_ac(&ac, d);
        println!("{:?}", r);
        let r = check_keyword_ac2(&ac2, d, &ac2_targets);
        println!("{:?}", r);
    }

    let ip_rules = rule_map.get(IP_CIDR).unwrap();
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

    let ip_rules = rule_map.get(IP_CIDR6).unwrap();
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
/// <https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes>
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
            s.domain_target_map = Some(get_item_target_map(v));
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
        let mt = method_rules_map.remove("MATCH");

        for (rt, item) in method_rules_map {
            for mut content in item {
                // println!("parsing {ss:?}");
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

        // println!("{:?}", s.rules);
        Ok(s)
    }
    #[cfg(feature = "serde_yaml_ng")]
    pub fn from_clash_config_str(cs: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let method_rules_map = parse_rules(&load_rules_from_str(cs)?);

        Ok(Self::from_hashmap(method_rules_map)?)
    }
    #[cfg(feature = "serde_yaml_ng")]
    pub fn from_clash_config_file<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error>> {
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
        if let Some(m) = &self.domain_regex_set {
            for (t, r) in m {
                if r.is_match(domain) {
                    return Some(t);
                }
            }
        }
        None
    }
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

#[derive(Default, Debug)]
pub struct RuleInput {
    pub domain: Option<String>,
    pub process_name: Option<String>,
    pub network: Option<String>,
    pub ip: Option<IpAddr>,
    pub dst_port: Option<u16>,

    /// for geoip
    #[cfg(feature = "maxminddb")]
    pub mmdb_reader: Option<std::sync::Arc<maxminddb::Reader<Vec<u8>>>>,
}

impl Rule {
    /// from normal rule. For logic rules use parse_rule
    pub fn from(r: &str, rule_type: &str) -> Result<Rule, ParseRuleError> {
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

#[derive(Error, Debug)]
pub enum ParseRuleError {
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
        Rule::from(r, rt)
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

#[cfg(feature = "rusqlite")]
use rusqlite::{params, Connection};

/// 初始化 SQLite 数据库，为每种规则类型创建一个独立的表
#[cfg(feature = "rusqlite")]
pub fn init_db(conn: &Connection) -> rusqlite::Result<()> {
    let target_sql = "CREATE TABLE targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL
    );";

    conn.execute(target_sql, [])?;

    let logic_group_sql = "CREATE TABLE logic_groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        logic TEXT NOT NULL CHECK (logic IN ('AND', 'OR', 'NOT')),
        target INTEGER, 
        parent_id INTEGER, 
        FOREIGN KEY (target) REFERENCES targets(id) ON DELETE CASCADE,
        FOREIGN KEY (parent_id) REFERENCES logic_groups(id) ON DELETE CASCADE
    );";

    conn.execute(logic_group_sql, [])?;
    let no_logic_rules = &RULE_TYPES[..RULE_TYPES.len() - 3];
    for &rn in no_logic_rules {
        let tn = to_sql_table_name(rn);

        let create_table_sql = format!(
            "CREATE TABLE IF NOT EXISTS {} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                target INTEGER, 
                logic_group_id INTEGER,
            FOREIGN KEY (target) REFERENCES targets(id) ON DELETE CASCADE,
            FOREIGN KEY (logic_group_id) REFERENCES logic_groups(id) ON DELETE CASCADE
            )",
            tn
        );
        conn.execute(&create_table_sql, [])?;

        let create_index_sql = format!("CREATE INDEX {}_index ON {} (content);", tn, tn);
        conn.execute(&create_index_sql, [])?;
    }

    // 创建 rules_view 视图
    let mut create_view_sql = "CREATE VIEW IF NOT EXISTS rules_view AS\n".to_string();
    let mut v = vec![];
    for &rn in no_logic_rules {
        let s = format!(
            "SELECT '{}' AS rule_name, content, target FROM {}",
            rn,
            to_sql_table_name(rn)
        );
        v.push(s);
    }
    let s = v.join("\nUNION ALL\n");
    create_view_sql = create_view_sql + &s + ";";

    conn.execute(&create_view_sql, [])?;

    Ok(())
}

/// query from all rule tables
///
/// eg: let sql = "SELECT rule_name, content, target FROM rules_view";
pub fn query_rules_view(
    conn: &Connection,
    sql: &str,
) -> rusqlite::Result<HashMap<String, Vec<Vec<String>>>> {
    let mut rules_map: HashMap<String, Vec<Vec<String>>> = HashMap::new();

    let mut stmt = conn.prepare("SELECT id, target FROM targets")?;
    let targets: HashMap<usize, String> = stmt
        .query_map([], |row| {
            let id: usize = row.get(0)?;
            let target: String = row.get(1)?;
            Ok((id, target))
        })?
        .map(|r| r.unwrap())
        .collect();
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |row| {
        let rule_name: String = row.get(0)?;
        let content: String = row.get(1)?;
        let target_label: usize = row.get(2)?;
        Ok((rule_name, content, target_label))
    })?;

    for row in rows {
        let (rule_name, c, ti) = row?;
        rules_map
            .entry(rule_name)
            .or_default()
            .push(vec![c, targets.get(&ti).unwrap().to_string()]);
    }

    Ok(rules_map)
}

pub fn insert_rule_with_target(
    conn: &rusqlite::Transaction,
    rule: &Rule,
    target: Option<&str>,
    parent_id: Option<i32>,
) -> rusqlite::Result<Option<i32>> {
    // println!("irwt {rule:?}");
    // 1.
    let target_id: Option<i32> = if target.is_some() {
        conn.execute(
        "INSERT INTO targets (target) SELECT ? WHERE NOT EXISTS (SELECT 1 FROM targets WHERE target = ?);",
        params![target, target],
    )?;
        conn.query_row(
            "SELECT id FROM targets WHERE target = ?;",
            params![target],
            |row| row.get(0),
        )?
    } else {
        None
    };

    match rule {
        Rule::And(rules) | Rule::Or(rules) => {
            // 2. 插入 logic_groups 表
            let logic_type = match rule {
                Rule::And(_) => AND,
                Rule::Or(_) => OR,
                _ => unreachable!(),
            };
            conn.execute(
                "INSERT INTO logic_groups (logic, target, parent_id) VALUES (?, ?, ?);",
                params![logic_type, target_id, parent_id],
            )?;
            let logic_group_id: i32 =
                conn.query_row("SELECT last_insert_rowid();", [], |row| row.get(0))?;

            // 3. 递归插入子规则
            for sub_rule in rules {
                insert_rule_with_target(conn, sub_rule, None, Some(logic_group_id))?;
            }

            Ok(Some(logic_group_id))
        }

        Rule::Not(sub_rule) => {
            // 2. 插入 logic_groups 表
            conn.execute(
                "INSERT INTO logic_groups (logic, target, parent_id) VALUES ('NOT', ?, ?);",
                params![target_id, parent_id],
            )?;
            let logic_group_id: i32 =
                conn.query_row("SELECT last_insert_rowid();", [], |row| row.get(0))?;

            // 3. 递归插入子规则
            insert_rule_with_target(conn, sub_rule, None, Some(logic_group_id))?;

            Ok(Some(logic_group_id))
        }

        // 4. 处理基础规则
        Rule::Domain(content)
        | Rule::DomainSuffix(content)
        | Rule::DomainKeyword(content)
        | Rule::GeoIp(content)
        | Rule::Network(content)
        | Rule::ProcessName(content) => {
            let table_name = match rule {
                Rule::Domain(_) => "domain",
                Rule::DomainSuffix(_) => "domain_suffix",
                Rule::DomainKeyword(_) => "domain_keyword",
                Rule::GeoIp(_) => "geoip",
                Rule::Network(_) => "network",
                Rule::ProcessName(_) => "process_name",
                _ => unreachable!(),
            };
            let query = format!(
                "INSERT INTO {} (content, target, logic_group_id) VALUES (?, ?, ?);",
                table_name
            );
            conn.execute(&query, params![content, target_id, parent_id])?;
            Ok(None)
        }

        Rule::IpCidr(ipn) => {
            let table_name = "ip_cidr";
            let query = format!(
                "INSERT INTO {} (content, target, logic_group_id) VALUES (?, ?, ?);",
                table_name
            );
            conn.execute(&query, params![ipn.to_string(), target_id, parent_id])?;
            Ok(None)
        }
        Rule::IpCidr6(ipn) => {
            let table_name = "ip_cidr6";
            let query = format!(
                "INSERT INTO {} (content, target, logic_group_id) VALUES (?, ?, ?);",
                table_name
            );
            conn.execute(&query, params![ipn.to_string(), target_id, parent_id])?;
            Ok(None)
        }

        Rule::DstPort(port) => {
            conn.execute(
                "INSERT INTO dst_port (content, target, logic_group_id) VALUES (?, ?, ?);",
                params![port, target_id, parent_id],
            )?;
            Ok(None)
        }

        Rule::Match => {
            conn.execute(
                "INSERT INTO match (content, target, logic_group_id) VALUES ('MATCH', ?, ?);",
                params![target_id, parent_id],
            )?;
            Ok(None)
        }

        Rule::Other(_rule_type, _content) => {
            // conn.execute(
            //     "INSERT INTO other (rule_type, content, target, logic_group_id) VALUES (?, ?, ?, ?);",
            //     params![rule_type, content, target_id, parent_id],
            // )?;
            Ok(None)
        }

        Rule::DomainRegex(r) => {
            let regex = r.to_string();
            conn.execute(
                "INSERT INTO domain_regex (content, target, logic_group_id) VALUES (?, ?, ?);",
                params![regex, target_id, parent_id],
            )?;
            Ok(None)
        }
    }
}

#[cfg(feature = "rusqlite")]
pub fn save_to_sqlite(
    conn: &mut Connection,
    rules: &HashMap<String, Vec<Vec<String>>>,
) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;

    for (rule_name, entries) in rules {
        if !RULE_TYPES.contains(&rule_name.as_str()) {
            continue;
        }
        if rule_name == AND || rule_name == OR || rule_name == NOT {
            for entry in entries {
                let mut e = entry.clone();
                let target = e.pop().unwrap();
                e.insert(0, rule_name.to_string());

                let s: String = e.join(",");
                let r = parse_rule(&s).unwrap();
                insert_rule_with_target(&tx, &r, Some(&target), None).unwrap();
            }
        } else {
            let table_name = to_sql_table_name(rule_name);

            for entry in entries {
                if entry.len() < 2 {
                    continue; // 确保 entry 格式正确：[内容, 目标标签]
                }
                let content = &entry[0];
                let target = &entry[1];

                add_rule(&tx, &table_name, content, target)?;
            }
        }
    }

    tx.commit()?;
    Ok(())
}

pub fn load_logic_rules_from_sqlite(conn: &Connection) -> rusqlite::Result<Vec<Rule>> {
    let mut stmt = conn.prepare("SELECT id FROM logic_groups WHERE parent_id IS NULL;")?;
    let ids: Vec<i32> = stmt
        .query_map(params![], |row| row.get(0))?
        .map(|r| r.unwrap())
        .collect();
    ids.into_iter()
        .map(|id| get_rule_from_logic_group(conn, id))
        .collect()
}
/// load normal rules
#[cfg(feature = "rusqlite")]
pub fn load_from_sqlite(conn: &Connection) -> rusqlite::Result<HashMap<String, Vec<Vec<String>>>> {
    let mut rules_map: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    let mut stmt = conn.prepare("SELECT id, target FROM targets")?;
    let targets: HashMap<usize, String> = stmt
        .query_map([], |row| {
            let id: usize = row.get(0)?;
            let target: String = row.get(1)?;
            Ok((id, target))
        })?
        .map(|r| r.unwrap())
        .collect();

    for &rn in &RULE_TYPES[..RULE_TYPES.len() - 3] {
        let rule_name = to_sql_table_name(rn);

        let mut stmt = conn.prepare(&format!(
            "SELECT content, target FROM {} where target IS NOT NULL",
            rule_name
        ))?;
        let rows = stmt.query_map([], |row| {
            let content: String = row.get(0)?;
            let target: usize = row.get(1)?;
            Ok((content, target))
        })?;

        for row in rows {
            let row = row?;
            rules_map
                .entry(to_clash_rule_name(&rule_name))
                .or_default()
                .push(vec![row.0, targets.get(&row.1).unwrap().to_string()]);
        }
    }

    Ok(rules_map)
}
/// add a normal rule
#[cfg(feature = "rusqlite")]
pub fn add_rule(
    tx: &rusqlite::Transaction,
    rule_table: &str,
    content: &str,
    target: &str,
) -> rusqlite::Result<()> {
    let rule_table = to_sql_table_name(rule_table);
    tx.execute(
        "INSERT INTO targets (target) SELECT ? WHERE NOT EXISTS (SELECT 1 FROM targets WHERE target = ?);",
        params![target, target],
    )?;
    let target_id: i32 = tx.query_row(
        "SELECT id FROM targets WHERE target = ?",
        params![target],
        |row| row.get(0),
    )?;

    let query = format!(
        "INSERT INTO {} (content, target) VALUES (?, ?);",
        rule_table
    );
    tx.execute(&query, params![content, target_id])?;

    Ok(())
}

/// delete a normal rule
#[cfg(feature = "rusqlite")]
pub fn delete_rule(conn: &Connection, rule_name: &str, content: &str) -> rusqlite::Result<()> {
    let table_name = to_sql_table_name(rule_name);
    let delete_sql = format!("DELETE FROM {} WHERE content = ?1", table_name);
    conn.execute(&delete_sql, params![content])?;
    Ok(())
}

/// update target for a normal rule
#[cfg(feature = "rusqlite")]
pub fn update_target(
    conn: &Connection,
    rule_table: &str,
    content: &str,
    new_target: &str,
) -> rusqlite::Result<()> {
    let rule_table = to_sql_table_name(rule_table);
    // 确保 new_target 在 targets 表中存在
    conn.execute(
        "INSERT INTO targets (target) SELECT ? WHERE NOT EXISTS (SELECT 1 FROM targets WHERE target = ?);",
        params![new_target, new_target],
    )?;

    let new_target_id: i32 = conn.query_row(
        "SELECT id FROM targets WHERE target = ?;",
        params![new_target],
        |row| row.get(0),
    )?;

    let query = format!("UPDATE {} SET target = ? WHERE content = ?;", rule_table);
    conn.execute(&query, params![new_target_id, content])?;

    Ok(())
}

/// get contents and targets for a normal rule
#[cfg(feature = "rusqlite")]
pub fn query_rule(conn: &Connection, rule_name: &str) -> rusqlite::Result<Vec<Vec<String>>> {
    let table_name = to_sql_table_name(rule_name);

    let mut stmt = conn.prepare(&format!(
        "
    SELECT r.content, t.target
    FROM {} r
    JOIN targets t ON r.target = t.id;
",
        table_name
    ))?;
    let rows = stmt.query_map([], |row| {
        let content: String = row.get(0)?;
        let target: String = row.get(1)?;
        Ok(vec![content, target])
    })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

fn get_rule_from_logic_group(conn: &Connection, logic_group_id: i32) -> rusqlite::Result<Rule> {
    // 获取当前 logic_group 规则类型
    let mut stmt = conn.prepare("SELECT logic FROM logic_groups WHERE id = ?;")?;
    let logic: String = stmt.query_row(params![logic_group_id], |row| row.get(0))?;

    // 递归获取子规则
    let mut stmt = conn.prepare("SELECT id FROM logic_groups WHERE parent_id = ?;")?;
    let child_logic_groups = stmt
        .query_map(params![logic_group_id], |row| row.get(0))?
        .collect::<Result<Vec<i32>, rusqlite::Error>>()?;

    let mut sub_rules = Vec::new();
    for &rn in &RULE_TYPES[..RULE_TYPES.len() - 3] {
        let rule_name = to_sql_table_name(rn);
        let mut stmt = conn.prepare(&format!(
            "SELECT content FROM {rule_name} WHERE logic_group_id = ?;"
        ))?;
        let rs = stmt
            .query_map(params![logic_group_id], |row| row.get(0))?
            .collect::<Result<Vec<String>, rusqlite::Error>>()?
            .into_iter()
            .map(|s| Rule::from(&s, rn).unwrap())
            .collect::<Vec<Rule>>();
        sub_rules.extend(rs);
    }

    for child_id in child_logic_groups {
        sub_rules.push(get_rule_from_logic_group(conn, child_id)?);
    }

    match logic.as_str() {
        "AND" => Ok(Rule::And(sub_rules)),
        "OR" => Ok(Rule::Or(sub_rules)),
        "NOT" => {
            if sub_rules.len() == 1 {
                Ok(Rule::Not(Box::new(sub_rules.into_iter().next().unwrap())))
            } else {
                Err(rusqlite::Error::QueryReturnedNoRows) // NOT 规则只能有一个子规则
            }
        }
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

#[cfg(feature = "rusqlite")]
#[test]
/// cargo test test_sql -- --nocapture
fn test_sql() -> rusqlite::Result<()> {
    println!("init");
    let _ = std::fs::remove_file("rules.db");
    let mut conn = Connection::open("rules.db")?;
    init_db(&conn)?;

    println!("rules");
    // 示例数据
    #[cfg(not(feature = "serde_yaml_ng"))]
    let mut rules: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    #[cfg(feature = "serde_yaml_ng")]
    let mut rules = parse_rules(&load_rules_from_file("test.yaml").unwrap());
    rules
        .entry("DOMAIN".to_string())
        .or_default()
        .append(&mut vec![
            vec!["example.com".to_string(), "proxy".to_string()],
            vec!["test.com".to_string(), "direct".to_string()],
        ]);
    rules
        .entry("IP-CIDR".to_string())
        .or_default()
        .append(&mut vec![
            vec!["192.168.1.0/24".to_string(), "proxy".to_string()],
            vec!["10.0.0.0/8".to_string(), "direct".to_string()],
        ]);
    let rule_str1 = "OR,((DOMAIN-KEYWORD,bili),(DOMAIN-REGEX,(?i)pcdn|mcdn)),direct".to_string();
    let rule_str2 = "AND,((DOMAIN-KEYWORD,bili),(DOMAIN-REGEX,(?i)pcdn|mcdn)),direct".to_string();
    let rule_str3 =
        "AND,((OR,((DOMAIN-KEYWORD,bili),(DOMAIN,0))),(DOMAIN-REGEX,(?i)pcdn|mcdn)),direct"
            .to_string();
    let rc = RuleConfig {
        rules: vec![rule_str1, rule_str2, rule_str3],
    };
    let h2 = parse_rules(&rc);
    println!("{h2:?}");
    let rules = merge_method_rules_map(rules, h2);

    println!("save");
    // 存入数据库
    save_to_sqlite(&mut conn, &rules)?;

    println!("load");
    // 读取数据库并恢复成 HashMap
    load_from_sqlite(&conn)?;
    let lrs = load_logic_rules_from_sqlite(&conn)?;
    println!("{lrs:?}");

    {
        println!("add");
        let tx = conn.transaction()?;

        add_rule(&tx, "DOMAIN", "example.com", "proxy")?;
        add_rule(&tx, "DOMAIN", "test.com", "direct")?;
        add_rule(&tx, "IP-CIDR", "192.168.1.0/24", "proxy")?;
    }

    println!("update");
    update_target(&conn, "DOMAIN", "test.com", "proxy")?;

    println!("query");
    // 查询特定规则
    let _domain_rules = query_rule(&conn, "DOMAIN")?;

    println!("delete");
    // 删除规则
    delete_rule(&conn, "DOMAIN", "example.com")?;

    let sql = "SELECT rule_name, content, target FROM rules_view WHERE target IS NOT NULL";
    println!("query view");
    let r = query_rules_view(&conn, sql)?;
    println!("all {:?}", r.len());

    Ok(())
}

/// 获取 `db` 中所有表的名称
#[cfg(feature = "rusqlite")]
fn get_table_names(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    )?;
    let tables = stmt
        .query_map([], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    Ok(tables)
}

/// 将 `db2.sqlite` 的数据合并到 `db1.sqlite`
#[cfg(feature = "rusqlite")]
pub fn merge_databases(db1_path: &str, db2_path: &str) -> rusqlite::Result<()> {
    let conn = Connection::open(db1_path)?;

    // 连接第二个数据库
    conn.execute(
        &format!("ATTACH DATABASE '{}' AS attached_db", db2_path),
        [],
    )?;

    // 获取 db2.sqlite 的所有表
    let tables = get_table_names(&conn)?;

    for table in tables {
        let sql = format!("INSERT INTO {table} SELECT * FROM attached_db.{table}");
        conn.execute(&sql, [])?;
    }

    // 断开连接
    conn.execute("DETACH DATABASE attached_db", [])?;

    Ok(())
}

#[cfg(feature = "rusqlite")]
#[test]
/// cargo test merge_sql -- --nocapture
fn merge_sql() -> rusqlite::Result<()> {
    let _ = std::fs::remove_file("1.db");
    let _ = std::fs::remove_file("2.db");
    {
        let mut conn = Connection::open("1.db")?;
        init_db(&conn)?;
        add_rule(&conn.transaction().unwrap(), "DOMAIN", "test.com", "direct")?;
        let mut conn = Connection::open("2.db")?;
        init_db(&conn)?;
        add_rule(
            &conn.transaction().unwrap(),
            "IP-CIDR",
            "192.168.1.0/24",
            "proxy",
        )?;
    }
    let db1 = "1.db";
    let db2 = "2.db";

    merge_databases(db1, db2)?;

    println!("Databases merged successfully!");
    Ok(())
}
