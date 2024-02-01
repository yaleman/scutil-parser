use scutil_parser::dns::parse_text;

use clap::{Parser, Subcommand};

#[derive(Subcommand)]
enum Commands {
    Dns,
}

#[derive(Parser)]
struct CliOpts {
    #[command(subcommand)]
    command: Commands,
}

fn rundns(_opts: CliOpts) {
    println!("Running DNS");
    // run scutil --dns and grab the result
    let output = std::process::Command::new("scutil")
        .arg("--dns")
        .output()
        .expect("failed to execute process");
    let output_string: String = std::str::from_utf8(&output.stdout).unwrap().to_string();
    let res = parse_text(&output_string).expect("Failed to parse result!");
    println!("{}", serde_json::to_string_pretty(&res).unwrap());
}

fn main() {
    let opts = CliOpts::parse();

    match opts.command {
        Commands::Dns => rundns(opts),
    }
}
