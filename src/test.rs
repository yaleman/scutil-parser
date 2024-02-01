use std::str::FromStr;

use crate::dns::{parse_text, ResolverFlags};

#[test]
fn test_from_file() {
    let filecontents = match std::fs::read_to_string("testdata.txt") {
        Ok(contents) => contents,
        Err(err) => panic!("Could not read file: {:?}", err),
    };
    println!("{}", filecontents);

    let res = match parse_text(&filecontents) {
        Ok(res) => res,
        Err(err) => panic!("Could not parse text: {:?}", err),
    };
    dbg!(&res);

    assert!(res.scoped_dns_config.len() == 1);
    assert!(res.dns_config.len() == 7);

    assert_eq!(res.scoped_dns_config[0].id, 1);
    assert_eq!(
        res.scoped_dns_config[0].search_domains,
        vec!["subdomain.example.com".to_string()]
    );
}

#[test]
fn test_flags_line() {
    let test_line = "  flags    : Scoped, Request A records, Request AAAA records";
    let test_line = test_line.trim().split(':').last().map(|s| s.trim());
    dbg!(&test_line);
    let test_line = test_line.expect("Failed to get tail");
    let res = test_line
        .split(',')
        .map(|s| ResolverFlags::from_str(s.trim()))
        .collect::<Result<Vec<ResolverFlags>, String>>();
    dbg!(&res);
    assert!(res.expect("failed to parse").len() == 3);
}
