// TODO: better f32 handling and rounding
// TODO: sigs, pointermaps, codecaves

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod data_type;
use data_type::DataType;
use strum::{EnumMessage, IntoEnumIterator};
mod scan;

use std::{io::Write, sync::mpsc::Receiver};

use memflow::prelude::v1::*;

use argh::FromArgs;
use serde::{Deserialize, Serialize};
use strum_macros::{EnumIter, EnumMessage};

use crate::scan::ScanType;

#[derive(FromArgs)]
/// memory view
struct Args {
    #[cfg(target_os = "linux")]
    /// memflow connector
    #[argh(positional)]
    connector: String,
    /// exe name
    #[argh(positional)]
    exe: String,
    /// default win32
    #[cfg(target_os = "linux")]
    #[argh(option, default = "String::from(\"win32\")")]
    os_chain: String,
}

fn main() {
    let args: Args = argh::from_env();
    #[cfg(target_os = "linux")]
    let os = {
        let inventory = memflow::plugins::Inventory::scan();
        let connector = args.connector.as_str();
        let os_chain = args.os_chain.as_str();
        let conn_iter = std::iter::once((0, connector));
        let os_iter = std::iter::once((0, os_chain));
        let chain = memflow::plugins::OsChain::new(conn_iter, os_iter)
            .map_err(|_| memflow::error::Error::from(memflow::error::ErrorKind::NotSupported))
            .unwrap();

        let os = inventory.builder().os_chain(chain).build().unwrap();
        os
    };

    #[cfg(target_os = "windows")]
    let os = {
        let path = r"C:\winio64.sys";
        if !std::path::Path::new(path).exists() {
            use std::io::Write;

            std::fs::File::create(path)
                .unwrap()
                .write_all(include_bytes!("../bin/winio64.sys"))
                .unwrap();
        }

        let connector = memflow_winio::create_connector(&ConnectorArgs::default()).unwrap();

        memflow_win32::prelude::Win32Kernel::builder(connector)
            .build_default_caches()
            .build()
            .unwrap()
    };

    let mut process = os
        .into_process_by_name(&args.exe)
        .expect("Process not found. Try running with --help to change exe name or launch the exe?");

    let module = process.primary_module().expect("Module not found.");

    println!("base: {}", module.base);
    println!("size: {}", module.size);

    let mut scan = scan::Scan::default();

    let mut hex = false;

    loop {
        print!("[{:?}] >> ", scan.settings.data_type);
        std::io::stdout().flush().unwrap(); // Ensures the prompt prints before input
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();

        let mut parts = input.split_whitespace();
        if let Some(command) = Command::from_str(parts.next().unwrap_or_default()) {
            match command {
                Command::Scan => {
                    if let Some(scan_type) = ScanType::from_str(parts.next().unwrap_or_default()) {
                        scan.settings.scan_type = scan_type;
                        let mut invalid_pattern = false;
                        let pattern: Option<Vec<Option<u8>>> = match scan_type {
                            ScanType::Pattern => Some(
                                parts
                                    .clone()
                                    .map(|byte| {
                                        if ["?", "??"].contains(&byte) {
                                            None
                                        } else if let Ok(byte) = u8::from_str_radix(byte, 0x10) {
                                            Some(byte)
                                        } else {
                                            invalid_pattern = true;
                                            None
                                        }
                                    })
                                    .collect(),
                            ),
                            ScanType::String => {
                                Some(parts.next().unwrap_or("").bytes().map(Some).collect())
                            }
                            _ => None,
                        };

                        if invalid_pattern {
                            println!("invalid pattern.");
                            continue;
                        }

                        if let Some(pattern) = &pattern {
                            if pattern.is_empty() {
                                println!("empty pattern/string.");
                                continue;
                            } else {
                                match scan_type {
                                    ScanType::Pattern => {
                                        scan.settings.data_type = DataType::Pattern(pattern.len())
                                    }
                                    ScanType::String => {
                                        scan.settings.data_type = DataType::String(pattern.len())
                                    }
                                    _ => {}
                                }
                            }
                        }

                        if let Err(error) = scan.scan(
                            process.clone(),
                            parts
                                .next()
                                .and_then(|str| scan.settings.data_type.bytes_from_str(str))
                                .as_deref(),
                            parts
                                .next()
                                .and_then(|str| scan.settings.data_type.bytes_from_str(str))
                                .as_deref(),
                            &pattern,
                        ) {
                            println!("{}", error);
                        }
                    } else {
                        println!("Invalid scan type. Available scan types: ");
                        for scan_type in ScanType::iter() {
                            println!(
                                "{} - {}",
                                serde_json::to_string(&scan_type).unwrap().replace("\"", ""),
                                scan_type.get_message().unwrap_or_default()
                            );
                        }
                        println!();
                    }
                }
                Command::Reinterpret => {
                    match DataType::from_str(parts.next().unwrap_or_default()) {
                        Some(dt) => {
                            scan.settings.data_type = dt;
                        }
                        None => {
                            print!("Invalid data type. Avalable options: ");
                            for data_type in DataType::iter() {
                                let mut data_type = serde_json::to_string(&data_type).unwrap();
                                for s in ["\"", "{", "}", ":0"] {
                                    data_type = data_type.replace(s, "");
                                }
                                print!("{} ", data_type);
                            }
                            println!();
                        }
                    }
                }
                Command::Print => {
                    if let Some(str) = parts.next() {
                        let mut start = 0;
                        let mut end = 0;
                        match str.trim() {
                            s if s.contains("-") => {
                                let (s, e) = s.split_once("-").unwrap();
                                if let (Ok(s), Ok(e)) = (
                                    usize::from_str_radix(s, 0x10),
                                    usize::from_str_radix(e, 0x10),
                                ) {
                                    start = s;
                                    end = e;
                                } else {
                                    println!("Invalid range.");
                                }
                            }
                            s => {
                                if let Ok(e) = usize::from_str_radix(s, 0x10) {
                                    end = e;
                                } else {
                                    println!("Invalid digit.")
                                }
                            }
                        }

                        let count = scan.get_result_count();
                        if end > count {
                            end = count;
                        }

                        if start == end {
                            println!("No results to print.");
                            continue;
                        }

                        println!("Printing results {}-{} out of {}:", start, end - 1, count);
                        for i in start..end {
                            if let Some(address) = scan.get_result(i) {
                                let bytes = process
                                    .read_raw(address, scan.settings.data_type.size())
                                    .unwrap();
                                println!(
                                    "{:X}: {}",
                                    address,
                                    scan.settings.data_type.to_string(&bytes, hex)
                                );
                            } else {
                                println!("failed to retreive result {}", i);
                            }
                        }
                    } else {
                        println!("{} results.", scan.get_result_count());
                        println!(
                            "To print results enter max number or range ({{start index}}-{{end index}}) after print command."
                        );
                    }
                }
                Command::FirstScan => {
                    scan.settings.cmp_first_scan = !scan.settings.cmp_first_scan;
                    println!("FirstScan toggled to {:?}", scan.settings.cmp_first_scan);
                }
                Command::Not => {
                    scan.settings.not = !scan.settings.not;
                    println!("Not toggled to {:?}", scan.settings.not);
                }
                Command::FastScan => {
                    if let Some(str) = parts.next() {
                        match str.trim() {
                            "off" => {
                                scan.settings.fast_scan = FastScan::Off;
                            }
                            "align" => {
                                scan.settings.fast_scan = FastScan::Align;
                            }
                            "last_digits" => {
                                if let Some(str) = parts.next() {
                                    if let Ok(digit) = u8::from_str_radix(str, 0x10) {
                                        if digit <= 0xF {
                                            scan.settings.fast_scan =
                                                FastScan::LastDigit(digit as usize);
                                        } else {
                                            println!("Digit too large.");
                                        }
                                    } else {
                                        println!("Invalid digit.");
                                    }
                                } else {
                                    println!("Digit required.");
                                }
                            }
                            _ => {
                                println!("Invalid option, type 'help' for options.");
                            }
                        }
                    } else {
                        println!("Invalid number of arguments.\n{}", command.help());
                    }
                }
                Command::ScanRange => {
                    if let Some(range) = parts.next() {
                        if let Some((s, e)) = range.trim().split_once("-") {
                            if let (Ok(start), Ok(end)) =
                                (u64::from_str_radix(s, 0x10), u64::from_str_radix(e, 0x10))
                            {
                                scan.settings.scan_range.0 = start.into();
                                scan.settings.scan_range.1 = end.into();
                                println!(
                                    "New scan range: {:X}-{:X}",
                                    scan.settings.scan_range.0, scan.settings.scan_range.1
                                );
                            } else {
                                println!("Invalid range.");
                            }
                        } else {
                            println!("Input must be a range.");
                        }
                    } else {
                        println!("Invalid number of arguments.\n{}", command.help());
                    }
                }
                Command::Status => {
                    let gap_size = 0;
                    let memory_map = process.mapped_mem_range_vec(
                        gap_size,
                        scan.settings.scan_range.0,
                        scan.settings.scan_range.1,
                    );
                    println!(
                        "Process size: {} MB",
                        memory_map.iter().map(|mr| mr.1).sum::<u64>() / 1024 / 1024
                    );
                    println!(
                        "Memory usage: {} MB",
                        scan.estimate_memory_usage() / 1024 / 1024
                    );
                    println!("Hex: {:?}", hex);
                    println!(
                        "Scan range: {:X}-{:X}",
                        scan.settings.scan_range.0, scan.settings.scan_range.1
                    );
                    println!("FastScan: {:?}", scan.settings.fast_scan);
                    println!("Compare to first scan: {:?}", scan.settings.cmp_first_scan);
                    println!("Not: {:?}", scan.settings.not);
                }
                Command::Reset => {
                    scan.reset();
                }
                Command::Hex => {
                    hex = !hex;
                    println!("Hex toggled to {:?}", hex);
                }
                Command::Add => {
                    if let Some(address) = parts.next() {
                        if let Ok(address) = u64::from_str_radix(address, 0x10) {
                            scan.add_address(address);
                        } else {
                            println!("invalid address.");
                        }
                    } else {
                        println!("missing address.");
                    }
                }
                Command::Write => {
                    if let (Some(address), Some(mode), Some(value)) =
                        (parts.next(), parts.next(), parts.next())
                    {
                        let get_line = match mode.to_lowercase().as_str() {
                            "o" | "once" => None,
                            "c" | "continuous" => {
                                println!("press enter to stop writing.");
                                Some(async_get_line())
                            }
                            _ => {
                                println!("Invalid argument.\n{}", command.help());
                                continue;
                            }
                        };

                        if let Some(bytes) = scan.settings.data_type.bytes_from_str(value) {
                            println!("Writing: {}", DataType::format_hex(&bytes));
                            loop {
                                if address == "*" {
                                    for i in 0..scan.get_result_count() {
                                        process
                                            .write_raw(scan.get_result(i).unwrap(), &bytes)
                                            .unwrap();
                                    }
                                } else if let Ok(address) = u64::from_str_radix(address, 0x10) {
                                    process.write_raw(address.into(), &bytes).unwrap();
                                } else {
                                    println!("Invalid address.");
                                    break;
                                }

                                if let Some(try_get_line) = &get_line {
                                    if let Ok(ret) = try_get_line.try_recv() {
                                        if let Err(e) = ret {
                                            println!("Error reading line: {}", e);
                                        }
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                            println!("Write done.");
                        } else {
                            println!("Invalid value.");
                        }
                    } else {
                        println!("Invalid number of arguments.\n{}", command.help());
                    }
                }
                Command::Help => {
                    println!("Commands: ");
                    for command in Command::iter() {
                        println!("{}", command.help());
                    }
                    println!();
                }
                Command::Quit => {
                    break;
                }
            }
        } else {
            println!("invalid command. type 'help' for usage info.");
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum FastScan {
    Off,
    Align,
    LastDigit(usize),
}

// TODO: add status thing to show currently selected options
// TODO: writeable/executable memory filters
#[derive(Deserialize, Serialize, Clone, Copy, EnumMessage, EnumIter, Debug)]
#[serde(rename_all = "snake_case")]
enum Command {
    #[strum(message = "run a scan. Alias: s")]
    Scan,
    #[strum(message = "change the data type. Alias: ri")]
    Reinterpret,
    #[strum(message = "print scan results. Alias: p")]
    Print,
    #[strum(message = "reset scan data and memory cache. Alias: r")]
    Reset,
    #[strum(message = "toggle hex mode. Default: off")]
    Hex,
    #[strum(message = "add address to results list. Alias a")]
    Add,
    #[strum(message = "write to a value. Alias: wr. Arguments: {address/*} {o/c} {value}")]
    Write,
    #[strum(message = "toggle comparing against first scan instead of last. Alias: fs")]
    FirstScan,
    #[strum(
        message = "invert match condition, applies to scan types: exact, value between, value within error."
    )]
    Not,
    #[strum(message = "skip some addresses. Default: align. Arguments: {off/align/last_digit}")]
    FastScan,
    #[strum(message = "set scan range, alias: sr. Arguments: {start address}-{end address}")]
    ScanRange,
    #[strum(message = "show current options and estimated memory usage.")]
    Status,
    #[strum(message = "print this message. Alias: h")]
    Help,
    #[strum(message = "exit the program. Alias: q")]
    Quit,
}

impl Command {
    fn from_str(str: &str) -> Option<Self> {
        if let Ok(command) = serde_json::from_str(&("\"".to_string() + &str.to_lowercase() + "\""))
        {
            Some(command)
        } else {
            match str.to_lowercase().as_str() {
                "wr" => Some(Self::Write),
                "s" => Some(Self::Scan),
                "ri" => Some(Self::Reinterpret),
                "p" => Some(Self::Print),
                "r" => Some(Self::Reset),
                "q" => Some(Self::Quit),
                "h" => Some(Self::Help),
                "sr" => Some(Self::ScanRange),
                "fs" => Some(Self::FirstScan),
                "a" => Some(Self::Add),
                _ => None,
            }
        }
    }

    fn help(&self) -> String {
        format!(
            "{} - {}",
            serde_json::to_string(&self).unwrap().replace("\"", ""),
            self.get_message().unwrap_or_default()
        )
    }
}

pub fn get_line() -> std::io::Result<String> {
    let mut output = String::new();
    std::io::stdin().read_line(&mut output).map(|_| output)
}

pub fn async_get_line() -> Receiver<std::io::Result<String>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || tx.send(get_line()).unwrap());
    rx
}
