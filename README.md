# Clash Rules &emsp; [![Latest Version]][crates.io]

[Latest Version]: https://img.shields.io/crates/v/clash_rules.svg
[crates.io]: https://crates.io/crates/clash_rules

This project can parse the rules and rule-sets in Clash’s YAML configuration files and provides optimized blazingly fast  matching algorithms.

The project uses functional programming.

DOMAIN-SUFFIX, IP-CIDR(6) uses radix trie, DOMAIN-KEYWORD uses Aho-Corasick Automaton.
DOMAIN-REGEX uses RegexSet. PORT uses binary search.

In general the algorithms are about 40x times faster than the unoptimized ones. If the cpu supports simd, DOMAIN-KEYWORD can speed up about 80x.

You can run `cargo bench` to test how fast the algorithm is on your machine.


For examples, see the test at the end of the lib.rs and benches/algorithms.

There's a convenient struct `ClashRuleMatcher` and an enum `Rule`.

Also has feature to load and save to sqlite.

Supported rules are:
RULE-SET, GEOSITE, AND, OR, NOT, DOMAIN, DOMAIN-KEYWORD, DOMAIN-SUFFIX, DOMAIN-REGEX,
IP-CIDR, IP-CIDR6, GEOIP, PROCESS-NAME, NETWORK, DST-PORT, SRC-PORT, IN-PORT, MATCH

Use external crate geosite-rs to support GEOSITE.
