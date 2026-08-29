use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

// maybe add str_utf16
#[derive(Deserialize, Serialize, Clone, Copy, EnumIter, Debug)]
#[serde(rename_all = "snake_case")]
pub enum DataType {
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    U64,
    I64,
    F32,
    F64,
    U128,
    I128,
    Pattern(usize),
    String(usize),
}

#[inline(always)]
pub fn cast<T: Copy>(bytes: &[u8]) -> T {
    assert!(bytes.len() >= size_of::<T>());
    let result: &[T] = unsafe { std::mem::transmute(bytes) };
    result[0]
}

#[inline(always)]
pub fn from_slice_at_offset(slice: &[u8], offset: usize, size: usize) -> Option<&[u8]> {
    if slice.len() < offset + size {
        return None;
    }

    Some(&slice[(offset)..(offset + size)])
}

#[rustfmt::skip]
#[macro_export]
macro_rules! gen_match {
    ($val:expr, $T:ident => $body:expr) => {
        match $val {
            DataType::U8  => { type $T = u8;  $body },
            DataType::I8  => { type $T = i8;  $body },
            DataType::U16 => { type $T = u16; $body },
            DataType::I16 => { type $T = i16; $body },
            DataType::U32 => { type $T = u32; $body },
            DataType::I32 => { type $T = i32; $body },
            DataType::U64 => { type $T = u64; $body },
            DataType::I64 => { type $T = i64; $body },
            DataType::F32 => { type $T = f32; $body },
            DataType::F64 => { type $T = f64; $body },
            DataType::U128 => { type $T = u128; $body },
            DataType::I128 => { type $T = i128; $body },
            _ => panic!("bug!"),
        }
    };
}

impl DataType {
    #[inline(always)]
    pub fn size(self) -> usize {
        match self {
            DataType::Pattern(size) => size,
            DataType::String(size) => size,
            _ => gen_match!(self, T => size_of::<T>()),
        }
    }

    #[inline(always)]
    pub fn align(self) -> usize {
        match self {
            DataType::Pattern(_) => 1,
            DataType::String(_) => 1,
            _ => gen_match!(self, T => size_of::<T>()),
        }
    }

    #[inline(always)]
    pub fn higher_than(self, a: &[u8], b: &[u8]) -> bool {
        gen_match!(self, T => cast::<T>(a) > cast::<T>(b))
    }

    #[inline(always)]
    pub fn lower_than(self, a: &[u8], b: &[u8]) -> bool {
        gen_match!(self, T => cast::<T>(a) < cast::<T>(b))
    }

    #[inline(always)]
    pub fn value_between(self, value: &[u8], start_range: &[u8], end_range: &[u8]) -> bool {
        self.higher_than(value, start_range) && self.lower_than(value, end_range)
    }

    // maybe impl for non floats?
    #[inline(always)]
    pub fn value_within_error(self, value: &[u8], target: &[u8], error: &[u8]) -> bool {
        match self {
            DataType::F32 => {
                (cast::<f32>(target) - cast::<f32>(error)) < cast::<f32>(value)
                    && cast::<f32>(value) < (cast::<f32>(target) + cast::<f32>(error))
            }
            DataType::F64 => {
                (cast::<f64>(target) - cast::<f64>(error)) < cast::<f64>(value)
                    && cast::<f64>(value) < (cast::<f64>(target) + cast::<f64>(error))
            }
            _ => value == target,
        }
    }

    #[inline(always)]
    pub fn higher_by(self, a: &[u8], b: &[u8], change: &[u8]) -> bool {
        gen_match!(self, T => (cast::<T>(a) + cast::<T>(change)) == cast::<T>(b))
    }

    #[inline(always)]
    pub fn lower_by(self, a: &[u8], b: &[u8], change: &[u8]) -> bool {
        gen_match!(self, T => (cast::<T>(a) - cast::<T>(change)) == cast::<T>(b))
    }

    #[inline(always)]
    #[allow(clippy::wrong_self_convention)]
    pub fn from_slice_at_offset(self, slice: &[u8], offset: u16) -> Option<&[u8]> {
        from_slice_at_offset(slice, offset as usize, self.size())
    }

    #[inline(always)]
    pub fn to_string(self, bytes: &[u8], hex: bool) -> String {
        if let DataType::String(_) = self {
            let mut bytes = bytes.to_vec();
            if let Some((n, _)) = bytes.iter().enumerate().find(|(_, c)| **c == 0_u8) {
                bytes.truncate(n);
            }

            if hex {
                return Self::format_hex(&bytes);
            } else {
                return String::from_utf8(bytes).unwrap_or("invalid utf8 encoding.".to_string());
            }
        }

        if let DataType::Pattern(_) = self {
            assert!(bytes.len() == self.size());
            return Self::format_hex(bytes);
        }

        if hex {
            assert!(bytes.len() == self.size());
            Self::format_hex(bytes).split_whitespace().collect()
        } else {
            gen_match!(self, T => cast::<T>(bytes).to_string())
        }
    }

    #[inline(always)]
    pub fn format_hex(bytes: &[u8]) -> String {
        let mut result = String::default();
        for byte in bytes {
            let string = format!("{:X} ", byte);
            if string.len() == 2 {
                result += &format!("0{}", string);
            } else {
                result += &string;
            }
        }
        result
    }

    #[rustfmt::skip]
    #[inline(always)]
    pub fn bytes_from_str(self, str: &str) -> Option<Vec<u8>> {
        match self {
            DataType::Pattern(_) => {
                return None;
            }
            DataType::String(size)  => {
                let mut bytes = str.as_bytes().to_vec();
                if bytes.len() >= size {
                    bytes.truncate(size);
                    return Some(bytes);
                } else {
                    return None;
                }
            }
            _ => {}
        }

        match str.trim().to_ascii_lowercase() {
            s if s.starts_with("0x") | "abcdef".chars().any(|c|s.contains(c))=> {
                let s = s.trim_start_matches("0x").trim();
                match self {
                    DataType::U8 => u8::from_str_radix(s, 0x10).ok().map(|a| a.to_le_bytes().to_vec()),
                    DataType::I8 => i8::from_str_radix(s, 0x10).ok().map(|a| a.to_le_bytes().to_vec()),
                    DataType::U16 => u16::from_str_radix(s, 0x10).ok().map(|a| a.to_le_bytes().to_vec()),
                    DataType::I16 => i16::from_str_radix(s, 0x10).ok().map(|a| a.to_le_bytes().to_vec()),
                    DataType::U32 => u32::from_str_radix(s, 0x10).ok().map(|a| a.to_le_bytes().to_vec()),
                    DataType::I32 => i32::from_str_radix(s, 0x10).ok().map(|a| a.to_le_bytes().to_vec()),
                    DataType::U64 => u64::from_str_radix(s, 0x10).ok().map(|a| a.to_le_bytes().to_vec()),
                    DataType::I64 => i64::from_str_radix(s, 0x10).ok().map(|a| a.to_le_bytes().to_vec()),
                    // stupid workaround for f32 and f64 not having a from_str_radix
                    DataType::F32 => u32::from_str_radix(s, 0x10).ok().map(|a| a.to_le_bytes().to_vec()),
                    DataType::F64 => u64::from_str_radix(s, 0x10).ok().map(|a| a.to_le_bytes().to_vec()),
                    DataType::U128 => u128::from_str_radix(s, 0x10).ok().map(|a| a.to_le_bytes().to_vec()),
                    DataType::I128 => i128::from_str_radix(s, 0x10).ok().map(|a| a.to_le_bytes().to_vec()),
                    _ => panic!("bug!"),
                }
            }
            s => {
                gen_match!(self, T => s.parse::<T>().ok().map(|a| a.to_le_bytes().to_vec()))
            }
        }
    }

    #[inline(always)]
    pub fn from_str(str: &str) -> Option<Self> {
        serde_json::from_str(&("\"".to_string() + &str.to_lowercase() + "\"")).ok()
    }
}
