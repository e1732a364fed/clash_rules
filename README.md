This project can parse the rules in Clash’s YAML configuration files and provides an optimized matching algorithm.
The project uses functional programming.

DOMAIN-SUFFIX, IP-CIDR(6) uses radix trie ，DOMAIN-KEYWORD uses Aho-Corasick Automaton.

For examples, see the test at the end of the lib.rs and benches/algorithms.

There's a convenient struct `ClashRuleMatcher`.

Also has feature to load and save to sqlite
