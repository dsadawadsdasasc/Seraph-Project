#[cfg(target_os = "windows")]
use crate::cache::TimedCacheValidator;
#[cfg(target_os = "linux")]
use memflow::prelude::v1::trait_group::c_void;
use memflow::prelude::v1::*;
use memflow::types::Address;
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
use rayon_tlsctx::ThreadLocalCtx;
use serde::{Deserialize, Serialize};
use std::{sync::Mutex, time::Duration};
use strum_macros::{EnumIter, EnumMessage};

#[cfg(target_os = "linux")]
pub type ProcessWrapper = IntoProcessInstance<'static, CBox<'static, c_void>, CArc<c_void>>;
#[cfg(target_os = "windows")]
pub type ProcessWrapper = memflow_win32::prelude::Win32Process<
    CachedPhysicalMemory<
        'static,
        MappedPhysicalMemory<
            &'static mut [u8],
            memflow_vdm::VdmContext<'static, memflow_winio::WinIoDriver>,
        >,
        TimedCacheValidator,
    >,
    CachedVirtualTranslate<DirectTranslate, TimedCacheValidator>,
    memflow_win32::prelude::Win32VirtualTranslate,
>;

use crate::{
    FastScan,
    data_type::{DataType, from_slice_at_offset},
};

pub type Addr = u64;

pub struct MemoryChunk {
    pub memory_range: MemoryRange,
    pub old_mem: Option<Vec<u8>>,
    pub first_mem: Option<Vec<u8>>,
    pub results: Vec<u16>,
}

impl MemoryChunk {
    fn new(memory_range: MemoryRange) -> Self {
        Self {
            memory_range,
            old_mem: None,
            first_mem: None,
            results: Vec::new(),
        }
    }

    #[inline(always)]
    fn scan(
        &mut self,
        settings: ScanSettings,
        process: &ThreadLocalCtx<ProcessWrapper, impl Fn() -> ProcessWrapper>,
        arg1: Option<&[u8]>,
        arg2: Option<&[u8]>,
        pattern: &Option<Vec<Option<u8>>>,
    ) {
        let ScanSettings {
            data_type,
            scan_type,
            fast_scan,
            scan_range: _,
            cmp_first_scan,
            not,
            first_scan,
        } = settings;

        let mem = unsafe {
            process
                .get()
                .read_raw(
                    self.memory_range.0,
                    self.memory_range.1 as usize + data_type.size(),
                )
                .data_part()
                .unwrap()
        };

        let results: Box<dyn Iterator<Item = u16> + Send> = if first_scan {
            let results =
                (0..self.memory_range.1 as usize + data_type.size()).map(|offset| offset as u16);
            match fast_scan {
                FastScan::Off => Box::new(results),
                FastScan::Align => Box::new(results.step_by(data_type.align())),
                FastScan::LastDigit(digit) => Box::new(results.skip(digit).step_by(0x10)),
            }
        } else if !self.results.is_empty() {
            Box::new(self.results.clone().into_iter())
        } else {
            self.old_mem = Some(mem);
            return;
        };

        if first_scan && self.first_mem.is_none() {
            self.first_mem = Some(mem.clone());
        }

        let old_mem = if !first_scan && cmp_first_scan {
            self.first_mem.clone()
        } else {
            self.old_mem.clone()
        };
        self.old_mem = Some(mem.clone());

        self.results = results
            .filter(move |offset| match scan_type {
                ScanType::Pattern | ScanType::String => {
                    if let Some(pattern) = pattern {
                        if let Some(bytes) =
                            from_slice_at_offset(&mem, (*offset) as usize, pattern.len())
                        {
                            bytes
                                .iter()
                                .zip(pattern)
                                .filter_map(|(b, p)| p.as_ref().map(|p| (b, p)))
                                .all(|(b, p)| b == p)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                ScanType::Exact => {
                    if let (Some(target), Some(bytes)) =
                        (arg1, data_type.from_slice_at_offset(&mem, *offset))
                    {
                        not ^ (bytes == target)
                    } else {
                        false
                    }
                }
                ScanType::Changed => {
                    if let Some(old_data) = &old_mem {
                        if let (Some(bytes), Some(old_bytes)) = (
                            data_type.from_slice_at_offset(&mem, *offset),
                            data_type.from_slice_at_offset(old_data, *offset),
                        ) {
                            bytes != old_bytes
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                ScanType::Unchanged => {
                    if let Some(old_data) = &old_mem {
                        if let (Some(bytes), Some(old_bytes)) = (
                            data_type.from_slice_at_offset(&mem, *offset),
                            data_type.from_slice_at_offset(old_data, *offset),
                        ) {
                            bytes == old_bytes
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                ScanType::Decreased => {
                    if let Some(old_data) = &old_mem {
                        if let (Some(bytes), Some(old_bytes)) = (
                            data_type.from_slice_at_offset(&mem, *offset),
                            data_type.from_slice_at_offset(old_data, *offset),
                        ) {
                            data_type.lower_than(bytes, old_bytes)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                ScanType::Increased => {
                    if let Some(old_data) = &old_mem {
                        if let (Some(bytes), Some(old_bytes)) = (
                            data_type.from_slice_at_offset(&mem, *offset),
                            data_type.from_slice_at_offset(old_data, *offset),
                        ) {
                            data_type.higher_than(bytes, old_bytes)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                ScanType::DecreasedBy => {
                    if let (Some(old_data), Some(arg1)) = (&old_mem, arg1) {
                        if let (Some(bytes), Some(old_bytes)) = (
                            data_type.from_slice_at_offset(&mem, *offset),
                            data_type.from_slice_at_offset(old_data, *offset),
                        ) {
                            data_type.lower_by(bytes, old_bytes, arg1)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                ScanType::IncreasedBy => {
                    if let (Some(old_data), Some(arg1)) = (&old_mem, arg1) {
                        if let (Some(bytes), Some(old_bytes)) = (
                            data_type.from_slice_at_offset(&mem, *offset),
                            data_type.from_slice_at_offset(old_data, *offset),
                        ) {
                            data_type.higher_by(bytes, old_bytes, arg1)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                ScanType::HigherThan => {
                    if let (Some(bytes), Some(arg1)) =
                        (data_type.from_slice_at_offset(&mem, *offset), arg1)
                    {
                        data_type.higher_than(bytes, arg1)
                    } else {
                        false
                    }
                }
                ScanType::LowerThan => {
                    if let (Some(bytes), Some(arg1)) =
                        (data_type.from_slice_at_offset(&mem, *offset), arg1)
                    {
                        data_type.lower_than(bytes, arg1)
                    } else {
                        false
                    }
                }
                ScanType::ValueBetween => {
                    if let (Some(bytes), Some(arg1), Some(arg2)) =
                        (data_type.from_slice_at_offset(&mem, *offset), arg1, arg2)
                    {
                        not ^ data_type.value_between(bytes, arg1, arg2)
                    } else {
                        false
                    }
                }
                ScanType::ValueWithinError => {
                    if let (Some(bytes), Some(arg1), Some(arg2)) =
                        (data_type.from_slice_at_offset(&mem, *offset), arg1, arg2)
                    {
                        not ^ data_type.value_within_error(bytes, arg1, arg2)
                    } else {
                        false
                    }
                }
                ScanType::UnknownValue | ScanType::Unset => panic!("bug!"),
            })
            .collect();

        if self.results.is_empty() {
            self.old_mem = None;
        }
    }
}

#[derive(Clone, Copy)]
pub struct ScanSettings {
    pub data_type: DataType,
    pub scan_type: ScanType,
    pub fast_scan: FastScan,
    pub scan_range: (Address, Address),
    pub cmp_first_scan: bool,
    pub not: bool,
    pub first_scan: bool,
}

impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            data_type: DataType::F32,
            scan_type: ScanType::Unset,
            fast_scan: FastScan::Align,
            scan_range: (Address::null(), Address::from((1 as umem) << 47)),
            cmp_first_scan: false,
            not: false,
            first_scan: true,
        }
    }
}

#[derive(Default)]
pub struct Scan {
    pub chunks: Vec<MemoryChunk>,
    pub settings: ScanSettings,
}

impl Scan {
    pub fn add_address(&mut self, address: Addr) {
        if let Some(chunk) = self.chunks.iter_mut().find(|chunk| {
            chunk.memory_range.0 >= address.into()
                && chunk.memory_range.0 + chunk.memory_range.1 <= address.into()
        }) {
            chunk
                .results
                .push((address - chunk.memory_range.0.to_umem()) as u16);
        } else {
            let index = self
                .chunks
                .iter()
                .enumerate()
                .find(|(_, chunk)| chunk.memory_range.0 > address.into())
                .map(|(i, _)| i)
                .unwrap_or(self.chunks.len());

            let base = Address::from(address - address % 0x1000);
            // TODO: get real page type?
            let mut chunk = MemoryChunk::new((base, 0x1000_u64, PageType::default()).into());

            chunk
                .results
                .push((address - chunk.memory_range.0.to_umem()) as u16);

            self.chunks.insert(index, chunk);
        }
    }

    pub fn estimate_memory_usage(&self) -> usize {
        self.chunks
            .iter()
            .map(|chunk| {
                std::mem::size_of_val(chunk.results.as_slice())
                    + chunk
                        .old_mem
                        .as_deref()
                        .map(std::mem::size_of_val)
                        .unwrap_or(0)
                    + chunk
                        .first_mem
                        .as_deref()
                        .map(std::mem::size_of_val)
                        .unwrap_or(0)
            })
            .sum()
    }

    pub fn get_result(&mut self, index: usize) -> Option<Address> {
        let mut sum = 0;
        for chunk in &self.chunks {
            if chunk.results.len() + sum > index {
                let offset = chunk.results.get(index - sum).unwrap();
                return Some(chunk.memory_range.0 + offset);
            }
            sum += chunk.results.len();
        }
        None
    }

    pub fn get_result_count(&self) -> usize {
        self.chunks.iter().map(|chunk| chunk.results.len()).sum()
    }

    pub fn reset(&mut self) {
        self.chunks.clear();
        self.settings.first_scan = true;
    }

    // TODO: make thing quicker
    pub fn scan(
        &mut self,
        mut process: ProcessWrapper,
        arg1: Option<&[u8]>,
        arg2: Option<&[u8]>,
        pattern: &Option<Vec<Option<u8>>>,
    ) -> std::result::Result<(), String> {
        if self.settings.first_scan {
            let gap_size = mem::mb(16) as i64;
            let mut memory_map = process.mapped_mem_range_vec(
                gap_size,
                self.settings.scan_range.0,
                self.settings.scan_range.1,
            );
            memory_map.sort_by_key(|memory_range| memory_range.0);

            self.chunks = memory_map
                .iter()
                .flat_map(|memory_range| {
                    (0..memory_range.1).step_by(0x1000).map(|offset| {
                        CTup3(
                            memory_range.0 + offset,
                            if memory_range.1 - offset < 0x1000 {
                                memory_range.1 - offset
                            } else {
                                0x1000
                            },
                            memory_range.2,
                        )
                    })
                })
                .map(MemoryChunk::new)
                .collect();
        }

        let process = ThreadLocalCtx::new_locked(move || process.clone());

        let pb = Mutex::new(pbr::ProgressBar::new(
            self.chunks.iter().map(|chunk| chunk.memory_range.1).sum(),
        ));
        pb.lock()
            .unwrap()
            .set_max_refresh_rate(Some(Duration::from_millis(50)));
        pb.lock().unwrap().set_units(pbr::Units::Bytes);

        let first_scan = self.settings.first_scan;
        let data_type = self.settings.data_type;
        let fast_scan = self.settings.fast_scan;

        if self.settings.scan_type == ScanType::UnknownValue {
            self.chunks.par_iter_mut().for_each(|chunk| {
                if first_scan {
                    let results = (0..chunk.memory_range.1 as usize + data_type.size())
                        .map(|offset| offset as u16);

                    chunk.results = match fast_scan {
                        FastScan::Off => results.collect(),
                        FastScan::Align => results.step_by(data_type.align()).collect(),
                        FastScan::LastDigit(digit) => results.skip(digit).step_by(0x10).collect(),
                    };
                }
                let mem = unsafe {
                    process
                        .get()
                        .read_raw(chunk.memory_range.0, chunk.memory_range.1 as usize)
                        .data_part()
                        .unwrap()
                };
                if first_scan {
                    chunk.first_mem = Some(mem.clone());
                }
                chunk.old_mem = Some(mem);
                pb.lock().unwrap().add(chunk.memory_range.1);
            });
        } else {
            self.chunks.par_iter_mut().for_each(|chunk| {
                pb.lock().unwrap().add(chunk.memory_range.1);
                chunk.scan(self.settings, &process, arg1, arg2, pattern);
            });
        }

        pb.lock().unwrap().finish();

        if self.settings.scan_type != ScanType::UnknownValue {
            self.chunks.retain(|chunk| !chunk.results.is_empty());
        }

        self.chunks
            .sort_by_key(|chunk| chunk.memory_range.0.to_umem());

        self.settings.first_scan = false;

        Ok(())
    }
}

#[derive(Deserialize, Serialize, Clone, Copy, EnumMessage, EnumIter, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    #[strum(message = "alias: pat")]
    Pattern,
    #[strum(message = "alias: str")]
    String,
    #[strum(message = "aliases: unk, ?")]
    UnknownValue,
    #[strum(message = "alias: =")]
    Exact,
    #[strum(message = "not inclusive. Arguments: {min} {max}")]
    ValueBetween,
    // TODO: change this?
    #[strum(message = "F32 and F64 only. Arguments: {target value} {error margin}")]
    ValueWithinError,
    #[strum(message = "alias: chng")]
    Changed,
    #[strum(message = "alias: unchng")]
    Unchanged,
    #[strum(message = "alias: <")]
    LowerThan,
    #[strum(message = "alias: >")]
    HigherThan,
    #[strum(message = "aliases: +, inc")]
    Increased,
    #[strum(message = "alias: inc_by")]
    IncreasedBy,
    #[strum(message = "aliases: -, dec")]
    Decreased,
    #[strum(message = "alias: dec_by")]
    DecreasedBy,
    #[strum(message = "")]
    Unset,
}

impl ScanType {
    pub fn from_str(str: &str) -> Option<Self> {
        if let Ok(scan_type) =
            serde_json::from_str(&("\"".to_string() + &str.to_lowercase() + "\""))
        {
            Some(scan_type)
        } else {
            match str.to_lowercase().as_str() {
                "pat" => Some(Self::Pattern),
                "str" => Some(Self::String),
                "unk" | "?" => Some(Self::UnknownValue),
                "=" => Some(Self::Exact),
                "chng" => Some(Self::Changed),
                "unchng" => Some(Self::Unchanged),
                "<" => Some(Self::LowerThan),
                ">" => Some(Self::HigherThan),
                "+" | "inc" => Some(Self::Increased),
                "inc_by" => Some(Self::IncreasedBy),
                "-" | "dec" => Some(Self::Decreased),
                "dec_by" => Some(Self::DecreasedBy),
                _ => None,
            }
        }
    }
}
