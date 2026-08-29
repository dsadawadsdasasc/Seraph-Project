import ctypes
import os
import sys

def compress_dll():
    dll_path = r"C:\unicorn\bin\unicorn.dll"
    if not os.path.exists(dll_path):
        print(f"Error: {dll_path} not found.")
        sys.exit(1)
        
    with open(dll_path, "rb") as f:
        data = f.read()
        
    ntdll = ctypes.windll.ntdll
    format_engine = 2 | 0x100  # COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM
    
    buffer_workspace_size = ctypes.c_ulong(0)
    fragment_workspace_size = ctypes.c_ulong(0)
    
    status = ntdll.RtlGetCompressionWorkSpaceSize(
        ctypes.c_ushort(format_engine),
        ctypes.byref(buffer_workspace_size),
        ctypes.byref(fragment_workspace_size)
    )
    if status != 0:
        print(f"Failed to get workspace size: {hex(status & 0xFFFFFFFF)}")
        sys.exit(1)
        
    workspace = ctypes.create_string_buffer(buffer_workspace_size.value)
    
    dest_size = len(data) + 4096
    dest_buf = ctypes.create_string_buffer(dest_size)
    final_size = ctypes.c_ulong(0)
    chunk_size = ctypes.c_ulong(4096)
    
    status = ntdll.RtlCompressBuffer(
        ctypes.c_ushort(format_engine),
        ctypes.c_char_p(data),
        ctypes.c_ulong(len(data)),
        dest_buf,
        ctypes.c_ulong(dest_size),
        chunk_size,
        ctypes.byref(final_size),
        workspace
    )
    if status != 0:
        print(f"Compression failed: {hex(status & 0xFFFFFFFF)}")
        sys.exit(1)
        
    out_path = r"unicorn.lznt1"
    with open(out_path, "wb") as f:
        f.write(dest_buf.raw[:final_size.value])
        
    print(f"Successfully compressed unicorn.dll to {out_path} ({final_size.value} bytes)")

if __name__ == "__main__":
    compress_dll()
