use regex::Regex;
use std::fs::File;
use std::io::{self, BufRead};

// Struktur untuk log Apache
#[derive(Debug, serde::Serialize)]
pub struct ApacheLogEntry {
    pub date: String,
    pub log_level: String,
    pub pid: String,
    pub message: String,
}

// Struktur untuk log Laravel
#[derive(Debug, serde::Serialize)]
pub struct LaravelLogEntry {
    pub date: String,
    pub log_level: String,
    pub message: String,
}

// Fungsi untuk menganalisis log Apache
pub fn analyze_apache_log(file_path: &str) -> Vec<ApacheLogEntry> {
    let file = File::open(file_path).expect("Unable to open file");
    let reader = io::BufReader::new(file);
    let mut log_entries = Vec::new();

    let log_pattern = Regex::new(r#"\[(?P<date>.+?)\] \[(?P<module>[^\:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+):.+?\] (?P<message>.+)"#).unwrap();

    for line in reader.lines() {
        if let Ok(log) = line {
            println!("Reading log line: {}", log); // Debugging output
            if let Some(captures) = log_pattern.captures(&log) {
                println!("Captured log entry: {:?}", captures); // Debugging output
                let entry = ApacheLogEntry {
                    date: captures["date"].to_string(),
                    log_level: captures["level"].to_string(),
                    pid: captures["pid"].to_string(),
                    message: captures["message"].to_string(),
                };
                log_entries.push(entry);
            } else {
                println!("No match for line: {}", log); // Debugging output
            }
        }
    }
    log_entries
}

pub fn analyze_laravel_log(file_path: &str) -> Vec<LaravelLogEntry> {
    let file = File::open(file_path).expect("Unable to open file");
    let reader = io::BufReader::new(file);
    let mut log_entries = Vec::new();

    // Regex untuk mendeteksi awal entri log Laravel
    let log_pattern = Regex::new(r#"\[(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (?P<env>\w+)\.(?P<level>\w+): (?P<message>.+)"#).unwrap();

    // Buffer untuk menyimpan baris log multi-line
    let mut current_entry: Option<LaravelLogEntry> = None;

    for line in reader.lines() {
        if let Ok(log) = line {
            // Jika menemukan garis yang cocok dengan pola log awal, simpan entri log sebelumnya dan mulai yang baru
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
                // Menambahkan baris tambahan ke pesan log jika ini adalah bagian dari multi-line log
                entry.message.push_str("\n");
                entry.message.push_str(&log);
            }
        }
    }

    // Menambahkan entri terakhir jika ada
    if let Some(entry) = current_entry {
        log_entries.push(entry);
    }

    log_entries
}
