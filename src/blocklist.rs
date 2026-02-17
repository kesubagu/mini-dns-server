use crate::types::DynError;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

pub fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

pub fn load_blocked_domains(path: &str) -> Result<HashSet<String>, DynError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut blocked_domains = HashSet::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        blocked_domains.insert(normalize_domain(trimmed));
    }

    Ok(blocked_domains)
}

pub fn save_blocked_domains(path: &str, blocked_domains: &HashSet<String>) -> Result<(), DynError> {
    let mut domains: Vec<_> = blocked_domains.iter().cloned().collect();
    domains.sort_unstable();

    let mut file = File::create(path)?;
    for domain in domains {
        writeln!(file, "{domain}")?;
    }

    Ok(())
}
