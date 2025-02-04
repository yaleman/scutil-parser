use regex::Regex;
use serde::Serialize;

use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Clone, Debug, Serialize)]
pub enum ResolverFlags {
    RequestARecords,
    RequestAAAARecords,
    Scoped,
}

impl FromStr for ResolverFlags {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Request A records" => Ok(ResolverFlags::RequestARecords),
            "Request AAAA records" => Ok(ResolverFlags::RequestAAAARecords),
            "Scoped" => Ok(ResolverFlags::Scoped),
            _ => Err(format!("Invalid resolver flag: {}", s)),
        }
    }
}

impl Display for ResolverFlags {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        match self {
            ResolverFlags::RequestARecords => write!(f, "Request A records"),
            ResolverFlags::RequestAAAARecords => write!(f, "Request AAAA records"),
            ResolverFlags::Scoped => write!(f, "Scoped"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceIndex {
    pub index: usize,
    pub interface: String,
}

impl FromStr for InterfaceIndex {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split(' ');
        let index: usize = split.nth(2).unwrap().parse().unwrap();
        let mut interface = split.last().unwrap_or("");
        if interface.starts_with('(') {
            interface = interface.strip_prefix('(').unwrap();
        }
        if interface.ends_with(')') {
            interface = interface.strip_suffix(')').unwrap();
        }

        Ok(Self {
            index,
            interface: interface.to_string(),
        })
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Resolver {
    pub id: usize,
    pub search_domains: Vec<String>,
    pub nameservers: HashMap<usize, IpAddr>,
    pub if_index: Option<InterfaceIndex>,
    pub flags: Vec<ResolverFlags>,
    pub reach: Option<String>,
    pub order: Option<usize>,
    pub domain: Option<String>,
    pub timeout: Option<usize>,
    pub options: Option<String>,
}

impl Resolver {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            ..Default::default()
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DNSConfig {
    pub dns_config: Vec<Resolver>,
    pub scoped_dns_config: Vec<Resolver>,
}

#[derive(Debug, Clone)]
enum ParserState {
    DnsConfig,
    ScopedDnsConfig,
    Resolver,
    ScopedResolver,
    Idle,
}

pub fn parse_text(input: &str) -> Result<DNSConfig, String> {
    let mut dns_config = DNSConfig {
        dns_config: Vec::new(),
        scoped_dns_config: Vec::new(),
    };

    let mut parent_state: ParserState = ParserState::Idle;
    let mut state: ParserState = ParserState::Idle;
    let mut current_resolver: Resolver = Resolver::new(0);

    let mut line_index = 0;
    let lines: Vec<String> = input.lines().map(|s| s.to_string()).collect();

    while line_index < lines.len() {
        let line = match lines.get(line_index) {
            Some(line) => line,
            None => {
                return Err(format!("Failed to get line index {}", line_index));
            }
        };

        #[cfg(test)]
        eprintln!("Parsing line: '{}'", line);
        if line.trim() == "DNS configuration" {
            #[cfg(test)]
            eprintln!("Setting state to ParserState::DnsConfig");
            state = ParserState::DnsConfig;
            parent_state = ParserState::DnsConfig;
            line_index += 2;
            continue;
        } else if line.trim() == "DNS configuration (for scoped queries)" {
            #[cfg(test)]
            eprintln!("Setting state to ParserState::ScopedDnsConfig");
            state = ParserState::ScopedDnsConfig;
            parent_state = ParserState::ScopedDnsConfig;
            line_index += 2;
            continue;
        }

        if line.starts_with("resolver") {
            let resolver_index: usize = line
                .split(' ')
                .last()
                .unwrap()
                .strip_prefix('#')
                .expect("Couldn't strip prefix off resolver line")
                .parse()
                .expect("Couldn't parse resolver index");

            match state {
                ParserState::DnsConfig => {
                    state = ParserState::Resolver;
                    #[cfg(test)]
                    eprintln!("Starting new resolver index {}", resolver_index);
                    current_resolver = Resolver::new(resolver_index);
                    line_index += 1;
                    continue;
                }
                ParserState::ScopedDnsConfig => {
                    state = ParserState::ScopedResolver;
                    #[cfg(test)]
                    eprintln!("Starting new scoped resolver index {}", resolver_index);
                    current_resolver = Resolver::new(resolver_index);
                    line_index += 1;
                    continue;
                }
                _ => {
                    return Err(format!(
                        "Unexpected resolver line: {} (state: {:?})",
                        line, state
                    ));
                }
            }
        }

        if line.trim().starts_with("nameserver") {
            #[cfg(test)]
            eprintln!("Handling nameserver");
            let nameserver = NAMESERVER_PARSER.captures(line.trim()).unwrap();
            let ns_id: usize = nameserver
                .name("ns_id")
                .unwrap()
                .as_str()
                .parse()
                .expect("Couldn't parse nameserver ID");
            let nameserver: IpAddr = nameserver
                .name("nameserver")
                .unwrap()
                .as_str()
                .parse()
                .expect("Couldn't parse nameserver IP");
            #[cfg(test)]
            eprintln!("Adding nameserver {} - {}", ns_id, nameserver);
            current_resolver.nameservers.insert(ns_id, nameserver);
        } else if line.trim().starts_with("search domain") {
            let search_domain = line.split(' ').last().map(|s| s.to_string());
            if let Some(search_domain) = search_domain {
                #[cfg(test)]
                eprintln!("Set search domain to {:?}", search_domain);
                current_resolver.search_domains.push(search_domain);
            }
        } else if line.trim().starts_with("if_index") {
            current_resolver.if_index = Some(InterfaceIndex::from_str(line.trim())?);
        } else if line.trim().starts_with("flags") {
            if let Some(flags) = line.trim().split(':').last().and_then(|l| {
                l.split(',')
                    .map(|s| ResolverFlags::from_str(s.trim()))
                    .collect::<Result<Vec<ResolverFlags>, String>>()
                    .ok()
            }) {
                current_resolver.flags = flags;
            };
        } else if line.trim().starts_with("reach") {
            let reach = line.trim().split(':').last().unwrap().trim();
            #[cfg(test)]
            eprintln!("Set reach to {}", reach);
            current_resolver.reach = Some(reach.to_string());
        } else if line.trim().starts_with("order") {
            let order = line.trim().split(':').last().unwrap().trim();
            let order: usize = order.parse::<usize>().map_err(|err| err.to_string())?;
            #[cfg(test)]
            eprintln!("Set order to {}", order);
            current_resolver.order = Some(order);
        } else if line.trim().starts_with("timeout") {
            let timeout = line.trim().split(':').last().unwrap().trim();
            let timeout: usize = timeout.parse::<usize>().map_err(|err| err.to_string())?;
            current_resolver.timeout = Some(timeout);
            #[cfg(test)]
            eprintln!("Set timeout to {}", timeout);
        } else if line.trim().starts_with("options") {
            let options = line.trim().split(':').last().unwrap().trim().to_string();
            #[cfg(test)]
            eprintln!("Set options to {}", options);
            current_resolver.options = Some(options);
        } else if line.trim().starts_with("domain") {
            let domain = line.trim().split(':').last().unwrap().trim().to_string();
            #[cfg(test)]
            eprintln!("Set domain to {}", domain);
            current_resolver.domain = Some(domain);
        } else if line.trim() == "" {
            match state {
                ParserState::Resolver => {
                    state = parent_state.clone();
                    #[cfg(test)]
                    eprintln!(
                        "Finished resolver index {} - {:?}",
                        current_resolver.id, current_resolver
                    );
                    dns_config.dns_config.push(current_resolver.clone());
                    line_index += 1;
                    continue;
                }
                ParserState::ScopedResolver => {
                    state = parent_state.clone();
                    #[cfg(test)]
                    eprintln!("Finished scoped resolver index {}", current_resolver.id);
                    dns_config.scoped_dns_config.push(current_resolver.clone());
                    line_index += 1;
                    continue;
                }
                ParserState::DnsConfig | ParserState::ScopedDnsConfig => {}
                _ => {
                    return Err(format!(
                        "Unexpected empty line: {} state: {:?}",
                        line, state
                    ));
                }
            }
        } else {
            return Err(format!("Unexpected line: {}", line));
        }
        line_index += 1;
    }
    // final cleanup bit
    // dbg!(&current_resolver);
    // dbg!(&state);

    match state {
        ParserState::Resolver => {
            if current_resolver.id != 0
                && current_resolver.nameservers.is_empty()
                && current_resolver.if_index.is_some()
            {
                dns_config.dns_config.push(current_resolver)
            }
        }
        ParserState::ScopedResolver => {
            if current_resolver.id != 0
                && !current_resolver.nameservers.is_empty()
                && current_resolver.if_index.is_some()
            {
                dns_config.scoped_dns_config.push(current_resolver)
            }
        }
        ParserState::ScopedDnsConfig => {}
        ParserState::DnsConfig => {}
        ParserState::Idle => {}
    }

    Ok(dns_config)
}

static NAMESERVER_PARSER: once_cell::sync::Lazy<Regex> = once_cell::sync::Lazy::new(|| {
    Regex::new(r"nameserver\[(?P<ns_id>\d+)\]\s+:\s+(?P<nameserver>\S+)")
        .expect("failed to generate retgex")
});
