use std::env;
use std::process::ExitCode;

use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use rayon::prelude::*;
use regex::Regex;
use tldextract::{TldExtractor, TldOption, TldResult};
use whois_rust::{WhoIs, WhoIsLookupOptions};

const SERVERS_JSON: &str = include_str!("../node-whois/servers.json");
const EMAIL_TEMPLATE: &str = include_str!("../email_template.txt");

fn main() -> ExitCode {
    let mut args = env::args();
    let executable = args.next().unwrap();
    let bad_urls: Vec<_> = args.collect();

    if bad_urls.is_empty() {
        eprintln!("Usage: {executable} <url> [urls...]");
        return ExitCode::FAILURE;
    }

    let results: Vec<_> = bad_urls
        .into_par_iter()
        .map(|s| (process_url(&s), s))
        .collect();

    for (res, url) in results {
        match res {
            Ok(output) => println!("{output}\n-------------------"),
            Err(why) => eprintln!("error processing {url}: {why:?}\n-------------------"),
        }
    }
    println!(
        "Remember to report each link using https://www.google.com/safebrowsing/report_phish/ ."
    );

    ExitCode::SUCCESS
}

static EXTRACTOR: Lazy<TldExtractor> = Lazy::new(|| TldOption::default().build());
static WHOIS: Lazy<WhoIs> = Lazy::new(|| {
    WhoIs::from_string(SERVERS_JSON)
    .expect("Could not parse the servers.json file.\nThis program was not compiled correctly - it should use the servers.json file from https://github.com/FurqanSoftware/node-whois")
});
static EMAIL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"Registrar Abuse Contact Email: (.+)").unwrap());

fn process_url(url: &str) -> Result<String> {
    let TldResult { domain: Some(domain), suffix: Some(suffix), .. } = EXTRACTOR.extract(url)? else {
        return Err(anyhow!("couldn't extract domain from url"));
    };

    let full_domain = format!("{domain}.{suffix}");
    let censored_domain = format!("{domain} [dot] {suffix}");
    let opts = WhoIsLookupOptions::from_str(&full_domain)?;
    let lookup = WHOIS.lookup(opts)?;

    let email_address = if let Some(cap) = EMAIL_REGEX.captures(&lookup) {
        cap.get(1).unwrap().as_str()
    } else {
        return Err(anyhow!("couldn't extract abuse email from whois reponse"));
    };

    let email = EMAIL_TEMPLATE
        .replace("[insert domain name]", &censored_domain)
        .replace(
            "[insert website link]",
            &url.replace(&full_domain, &censored_domain),
        );

    Ok(format!("RECEPIENT: {email_address}\nMESSAGE:\n{email}"))
}
