use super::*;
use rusqlite::{params, Connection};

/// 初始化 SQLite 数据库，为每种规则类型创建一个独立的表
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

pub fn save(
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

pub fn load_logic_rules(conn: &Connection) -> rusqlite::Result<Vec<Rule>> {
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
pub fn load(conn: &Connection) -> rusqlite::Result<HashMap<String, Vec<Vec<String>>>> {
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
pub fn delete_rule(conn: &Connection, rule_name: &str, content: &str) -> rusqlite::Result<()> {
    let table_name = to_sql_table_name(rule_name);
    let delete_sql = format!("DELETE FROM {} WHERE content = ?1", table_name);
    conn.execute(&delete_sql, params![content])?;
    Ok(())
}

/// update target for a normal rule
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
            .map(|s| Rule::from_content_type(&s, rn).unwrap())
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
    save(&mut conn, &rules)?;

    println!("load");
    // 读取数据库并恢复成 HashMap
    load(&conn)?;
    let lrs = load_logic_rules(&conn)?;
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
