This project can parse the rules in Clash’s YAML configuration files and provides an optimized matching algorithm.
The project uses functional programming.

DOMAIN-SUFFIX, IP-CIDR(6) uses radix trie ，DOMAIN-KEYWORD uses Aho-Corasick Automaton.
DOMAIN-REGEX uses RegexSet.

For examples, see the test at the end of the lib.rs and benches/algorithms.

There's a convenient struct `ClashRuleMatcher` and an enum `Rule`.

Also has feature to load and save to sqlite.

Supported rules are:
RULE-SET, AND, OR, NOT, DOMAIN, DOMAIN-KEYWORD, DOMAIN-SUFFIX, DOMAIN-REGEX,
IP-CIDR, IP-CIDR6, GEOIP, PROCESS-NAME, NETWORK, DST-PORT, SRC-PORT, IN-PORT, MATCH
