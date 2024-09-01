use regex::Regex;
use std::ffi::CString;
use std::os::raw::c_char;
use std::io::BufRead;

#[derive(Debug, serde::Serialize)]
pub struct ApacheLogEntry {
    pub date: String,
    pub log_level: String,
    pub pid: String,
    pub message: String,
}

#[derive(Debug, serde::Serialize)]
pub struct LaravelLogEntry {
    pub date: String,
    pub log_level: String,
    pub message: String,
}

#[no_mangle]
pub extern "C" fn analyze_laravel_log(file_path: *const c_char) -> *mut c_char {
    let c_str = unsafe { std::ffi::CStr::from_ptr(file_path) };
    let file_path = c_str.to_str().unwrap();
    
    let entries = analyze_laravel_log_internal(file_path);
    let json = serde_json::to_string(&entries).unwrap();

    CString::new(json).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn analyze_apache_log(file_path: *const c_char) -> *mut c_char {
    let c_str = unsafe { std::ffi::CStr::from_ptr(file_path) };
    let file_path = c_str.to_str().unwrap();

    let entries = analyze_apache_log_internal(file_path);
    let json = serde_json::to_string(&entries).unwrap();

    CString::new(json).unwrap().into_raw()
}

fn analyze_laravel_log_internal(file_path: &str) -> Vec<LaravelLogEntry> {
    let file = std::fs::File::open(file_path).expect("Unable to open file");
    let reader = std::io::BufReader::new(file);
    let mut log_entries = Vec::new();

    let log_pattern = Regex::new(r#"\[(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (?P<env>\w+)\.(?P<level>\w+): (?P<message>.+)"#).unwrap();

    let mut current_entry: Option<LaravelLogEntry> = None;

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
}

fn analyze_apache_log_internal(file_path: &str) -> Vec<ApacheLogEntry> {
    let file = std::fs::File::open(file_path).expect("Unable to open file");
    let reader = std::io::BufReader::new(file);
    let mut log_entries = Vec::new();

    let log_pattern = Regex::new(r#"\[(?P<date>.+?)\] \[(?P<module>[^\:]+):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+):.+?\] (?P<message>.+)"#).unwrap();

    for line in reader.lines() {
        if let Ok(log) = line {
            if let Some(captures) = log_pattern.captures(&log) {
                let entry = ApacheLogEntry {
                    date: captures["date"].to_string(),
                    log_level: captures["level"].to_string(),
                    pid: captures["pid"].to_string(),
                    message: captures["message"].to_string(),
                };
                log_entries.push(entry);
            }
        }
    }

    log_entries
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if s.is_null() { return; }
    // Menangani hasil CString dengan drop untuk membersihkan memori
    unsafe { drop(CString::from_raw(s)); }
}
