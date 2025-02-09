本项目可解析 clash 的 yaml 配置文件中的 rules 规则，并提供经优化后的匹配算法。

项目使用函数式编程。

DOMAIN-SUFFIX, IP-CIDR（6）采用 radix trie ，DOMAIN-KEYWORD 采用 AC 自动机（Aho-Corasick Automaton）
