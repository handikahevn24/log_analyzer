use clap::{Arg, Command}; // Import clap
use regex::Regex;
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{BufRead, BufReader};
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use std::env;

#[derive(Debug, Serialize)]
pub struct ApacheLogEntry {
    date: String,
    log_level: String,
    pid: String,
    message: String,
}

#[derive(Debug, Serialize)]
pub struct LaravelLogEntry {
    date: String,
    log_level: String,
    message: String,
}

#[derive(Debug, Serialize)]
pub struct AccessLogEntry {
    ip: String,
    datetime: String,
    method: String,
    url: String,
    protocol: String,
    status: String,
    size: String,
    referrer: String,
    user_agent: String,
}

fn main() {
    // Definisikan command line argument menggunakan clap
    let matches = Command::new("Log Analyzer")
        .version("1.0")
        .author("Developer")
        .about("Analyzes Apache, Laravel, and Access log files")
        .arg(
            Arg::new("laravel")
                .long("laravel")
                .conflicts_with_all(&["apache", "access"])
                .help("Indicates the log is a Laravel log")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("apache")
                .long("apache")
                .conflicts_with_all(&["laravel", "access"])
                .help("Indicates the log is an Apache log")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("access")
                .long("access")
                .conflicts_with_all(&["laravel", "apache"])
                .help("Indicates the log is an Access log")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("log_path")
                .help("Path to the log file")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("date")
                .long("date")
                .num_args(1)
                .help("Filter logs by date (e.g., 2024-08-22)"),
        )
        .arg(
            Arg::new("type")
                .long("type")
                .num_args(1)
                .help("Filter logs by error type (e.g., ERROR)"),
        )
        .arg(
            Arg::new("status")
                .long("status")
                .num_args(1)
                .help("Filter Access logs by HTTP status code (e.g., 200, 404)"),
        )
        .arg(
            Arg::new("method")
                .long("method")
                .num_args(1)
                .help("Filter Access logs by HTTP method (e.g., GET, POST)"),
        )
        .get_matches();

    // Mengambil nilai argumen
    let log_path = matches.get_one::<String>("log_path").unwrap();
    let date_filter = matches.get_one::<String>("date").map(|s| s.as_str());
    let error_type = matches.get_one::<String>("type").map(|s| s.as_str());
    let status_filter = matches.get_one::<String>("status").map(|s| s.as_str());
    let method_filter = matches.get_one::<String>("method").map(|s| s.as_str());

    // Menentukan jenis log berdasarkan flag
    if matches.get_flag("laravel") {
        let results = analyze_laravel_log(log_path, date_filter, error_type);
        print_json(&results);
        write_json_to_file(&results, "laravel_log_output.json");
    } else if matches.get_flag("apache") {
        let results = analyze_apache_log(log_path, date_filter, error_type);
        print_json(&results);
        write_json_to_file(&results, "apache_log_output.json");
    } else if matches.get_flag("access") {
        let results = analyze_access_log(log_path, status_filter, method_filter);
        print_json(&results);
        write_json_to_file(&results, "access_log_output.json");
    } else {
        eprintln!("Please specify the log type with --laravel, --apache, or --access.");
    }
}

// Fungsi untuk mencetak hasil dalam format JSON
fn print_json<T: Serialize>(results: &T) {
    match serde_json::to_string_pretty(results) {
        Ok(json) => println!("{}", json), // Cetak JSON yang diformat rapi ke terminal
        Err(e) => eprintln!("Failed to convert to JSON: {}", e),
    }
}

fn write_json_to_file<T: Serialize>(results: &T, file_name: &str) {
    // Tentukan path berdasarkan sistem operasi
    let file_path = if cfg!(target_os = "windows") {
        // Windows: Simpan di direktori saat ini
        let current_dir = env::current_dir().expect("Failed to get current directory");
        current_dir.join(file_name)
    } else {
        // Linux: Simpan di direktori user, misalnya ~/logs
        let mut user_dir = env::var("HOME").map(PathBuf::from).expect("Failed to get HOME directory");
        user_dir.push("logs");

        // Buat direktori jika belum ada
        if !user_dir.exists() {
            create_dir_all(&user_dir).expect("Failed to create logs directory");
        }

        user_dir.join(file_name)
    };

    // Konversi PathBuf ke String untuk menampilkan path
    let file_path_str = file_path.to_str().expect("Failed to convert path to string");

    match serde_json::to_string_pretty(results) {
        Ok(json) => {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&file_path)
                .expect("Unable to open file");
            if let Err(e) = file.write_all(json.as_bytes()) {
                eprintln!("Failed to write to file: {}", e);
            } else {
                println!("Output saved to {}", file_path_str);
            }
        }
        Err(e) => eprintln!("Failed to convert to JSON: {}", e),
    }
}

fn analyze_laravel_log(file_path: &str, date_filter: Option<&str>, error_type: Option<&str>) -> Vec<LaravelLogEntry> {
    let file = File::open(file_path).expect("Unable to open file");
    let reader = BufReader::new(file);
    let mut log_entries = Vec::new();
    let mut current_entry: Option<LaravelLogEntry> = None;

    let log_pattern = Regex::new(r#"\[(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (?P<env>\w+)\.(?P<level>\w+): (?P<message>.+)"#).unwrap();

    for line in reader.lines() {
        if let Ok(log) = line {
            if let Some(captures) = log_pattern.captures(&log) {
                if let Some(entry) = current_entry.take() {
                    log_entries.push(entry);
                }
                current_entry = Some(LaravelLogEntry {
                    date: captures["date"].to_string(),
                    log_level: captures["level"].to_string(),
                    message: captures["message"].to_string(),
                });
            } else if let Some(ref mut entry) = current_entry {
                entry.message.push_str("\n");
                entry.message.push_str(&log);
            }
        }
    }

    if let Some(entry) = current_entry {
        log_entries.push(entry);
    }

    log_entries
        .into_iter()
        .filter(|entry| {
            let date_matches = date_filter.map_or(true, |filter| entry.date.contains(filter));
            let error_matches = error_type.map_or(true, |filter| entry.log_level.eq_ignore_ascii_case(filter));
            date_matches && error_matches
        })
        .collect()
}

pub fn analyze_apache_log(file_path: &str, date_filter: Option<&str>, error_type: Option<&str>) -> Vec<ApacheLogEntry> {
    let file = File::open(file_path).expect("Unable to open file");
    let reader = BufReader::new(file);
    let mut log_entries = Vec::new();

    let log_pattern = Regex::new(r#"\[(?P<date>[A-Za-z]{3} [A-Za-z]{3} \d{2} \d{2}:\d{2}:\d{2}\.\d+ \d{4})\] \[(?P<module>[^\:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)(?::tid \d+)?\](?: \[client (?P<client>[^\]]+)\])? (?P<message>.+)"#).unwrap();

    for line in reader.lines() {
        if let Ok(log) = line {
            println!("Reading log line: {}", log); // Debugging output
            if let Some(captures) = log_pattern.captures(&log) {
                println!("Captured log entry: {:?}", captures); // Debugging output
                let date = &captures["date"];
                let log_level = &captures["level"];

                let date_matches = date_filter.map_or(true, |filter| date.contains(filter));
                let error_matches = error_type.map_or(true, |filter| log_level.eq_ignore_ascii_case(filter));

                if date_matches && error_matches {
                    log_entries.push(ApacheLogEntry {
                        date: date.to_string(),
                        log_level: log_level.to_string(),
                        pid: captures["pid"].to_string(),
                        message: captures["message"].to_string(),
                    });
                }
            } else {
                println!("No match for line: {}", log); // Debugging output
            }
        }
    }

    log_entries
}

pub fn analyze_access_log(file_path: &str, status_filter: Option<&str>, method_filter: Option<&str>) -> Vec<AccessLogEntry> {
    let file = File::open(file_path).expect("Unable to open file");
    let reader = BufReader::new(file);
    let mut log_entries = Vec::new();

    let log_pattern = Regex::new(r#"(?P<ip>\S+) - - \[(?P<datetime>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\d+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"#).unwrap();

    for line in reader.lines() {
        if let Ok(log) = line {
            if let Some(captures) = log_pattern.captures(&log) {
                let ip = captures["ip"].to_string();
                let datetime = captures["datetime"].to_string();
                let method = captures["method"].to_string();
                let url = captures["url"].to_string();
                let protocol = captures["protocol"].to_string();
                let status = captures["status"].to_string();
                let size = captures["size"].to_string();
                let referrer = captures["referrer"].to_string();
                let user_agent = captures["user_agent"].to_string();

                let status_matches = status_filter.map_or(true, |filter| status == filter);
                let method_matches = method_filter.map_or(true, |filter| method.eq_ignore_ascii_case(filter));

                if status_matches && method_matches {
                    log_entries.push(AccessLogEntry {
                        ip,
                        datetime,
                        method,
                        url,
                        protocol,
                        status,
                        size,
                        referrer,
                        user_agent,
                    });
                }
            } else {
                println!("No match for line: {}", log); // Debugging output
            }
        }
    }

    log_entries
}
