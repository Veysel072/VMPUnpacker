#!/usr/bin/env python3
import os
import sys
import struct
import lzma
import ctypes
from typing import List, Tuple, Optional
from dataclasses import dataclass
import io
import pefile  # Added pefile library import

# PE file format constants
IMAGE_DOS_SIGNATURE = 0x5A4D  # MZ
IMAGE_NT_SIGNATURE = 0x00004550  # PE\0\0
IMAGE_SIZEOF_SHORT_NAME = 8
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
LZMA_PROPERTIES_SIZE = 5  # Standard LZMA properties size

@dataclass
class PACKER_INFO:
    """Python implementation corresponding to C++ struct"""
    Src: int  # uint32
    Dst: int  # uint32

def to_hex_string(val, prefix=True):
    """Convert value to hexadecimal string for better error message display"""
    return f"0x{val:x}" if prefix else f"{val:x}"

def find_pattern(data: bytes, pattern: bytes) -> Optional[int]:
    """
    Find pattern in data, supporting 0xFF as wildcard
    Returns position where found, or None if not found
    """
    if not pattern or len(data) < len(pattern):
        return None
    
    for i in range(len(data) - len(pattern) + 1):
        match = True
        for j in range(len(pattern)):
            if pattern[j] != 0xFF and data[i + j] != pattern[j]:
                match = False
                break
        if match:
            return i
    return None

def unpack_pe(packed_pe_data: bytes) -> bytes:
    """
    Unpack a VMProtect protected PE file
    
    Args:
        packed_pe_data: Byte content of the packed PE file
        
    Returns:
        Unpacked PE file byte content
    """
    if not packed_pe_data:
        raise RuntimeError("Packed PE data is null or empty.")
    
    # Use pefile library to parse PE file
    try:
        pe = pefile.PE(data=packed_pe_data)
    except pefile.PEFormatError as e:
        raise RuntimeError(f"Invalid PE file format: {str(e)}")
    
    # Get basic PE information
    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders
    number_of_sections = pe.FILE_HEADER.NumberOfSections
    
    # Create unpacked image
    unpacked_image = bytearray(size_of_image)
    
    # Copy PE headers
    unpacked_image[:size_of_headers] = packed_pe_data[:size_of_headers]
    
    # Collect RVA patterns to locate PACKER_INFO array
    rva_patterns_array = []
    for section in pe.sections:
        # Check conditions: no raw data but has virtual address, and not uninitialized data section
        condition1 = (section.SizeOfRawData == 0)
        condition2 = (section.PointerToRawData == 0)
        condition3 = not (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
        
        if condition1 and condition2 and condition3:
            # 64-bit mode: high 32 bits is VirtualAddress, low 32 bits is 0xFFFFFFFF (wildcard)
            pattern_value = ((section.VirtualAddress << 32) | 0xFFFFFFFF) & 0xFFFFFFFFFFFFFFFF
            pattern_bytes = struct.pack("<Q", pattern_value)
            rva_patterns_array.append(pattern_bytes)
    
    # Find PACKER_INFO array
    packer_info_array = []
    num_packer_entries = 0
    
    if rva_patterns_array:
        # Convert patterns to a single byte sequence
        pattern_bytes = b''.join(rva_patterns_array)
        
        # Search for pattern
        pattern_pos = find_pattern(packed_pe_data, pattern_bytes)
        
        if pattern_pos is not None:
            # PACKER_INFO array is located before the matching pattern sequence
            if pattern_pos < 8:  # sizeof(PACKER_INFO) = 8
                raise RuntimeError("Located RVA pattern is too close to the beginning of the file to precede PACKER_INFO[0].")
            
            packer_info_offset = pattern_pos - 8
            num_packer_entries = len(rva_patterns_array)
            
            # Verify reading this array won't go beyond packed_pe_data boundaries
            if num_packer_entries > 0:
                end_of_packer_info_array = packer_info_offset + (num_packer_entries + 1) * 8
                if end_of_packer_info_array > len(packed_pe_data) or packer_info_offset < 0:
                    raise RuntimeError("Located PACKER_INFO array extends beyond packed PE buffer or has invalid start.")
            
            # Extract PACKER_INFO array
            for j in range(num_packer_entries + 1):  # +1 because original code includes the first entry
                info_offset = packer_info_offset + j * 8
                src = struct.unpack("<I", packed_pe_data[info_offset:info_offset+4])[0]
                dst = struct.unpack("<I", packed_pe_data[info_offset+4:info_offset+8])[0]
                packer_info_array.append(PACKER_INFO(src, dst))
        
        elif rva_patterns_array:
            raise RuntimeError("RVA pattern sequence for PACKER_INFO not found in packed PE, but patterns were expected.")
    else:
        print("Warning: RVA pattern array is empty. No PACKER_INFO entries to process for LZMA.")
    
    # Copy section data and update section headers in unpacked image
    for i, section in enumerate(pe.sections):
        # Original section header
        virtual_address = section.VirtualAddress
        virtual_size = section.Misc_VirtualSize
        size_of_raw_data = section.SizeOfRawData
        pointer_to_raw_data = section.PointerToRawData
        section_name = section.Name.decode('ascii', errors='ignore').strip('\0')
        
        # Copy section data
        if pointer_to_raw_data != 0 and size_of_raw_data > 0:
            if pointer_to_raw_data + size_of_raw_data <= len(packed_pe_data) and virtual_address + size_of_raw_data <= size_of_image:
                section_data = packed_pe_data[pointer_to_raw_data:pointer_to_raw_data+size_of_raw_data]
                unpacked_image[virtual_address:virtual_address+len(section_data)] = section_data
            else:
                print(f"Warning: Section {section_name} data exceeds boundaries. RawOffset={to_hex_string(pointer_to_raw_data)}, "
                      f"RawSize={to_hex_string(size_of_raw_data)}, VA={to_hex_string(virtual_address)}. Skipping copy.")
        
        # Get section table offset in file
        section_offset = pe.OPTIONAL_HEADER.get_file_offset() + pe.FILE_HEADER.SizeOfOptionalHeader + i * 40
        
        # Update section header in unpacked image
        unpacked_section_offset = section_offset
        
        # Update PointerToRawData to VirtualAddress
        struct.pack_into("<I", unpacked_image, unpacked_section_offset+20, virtual_address)
        
        # If VirtualSize is non-zero, use it as SizeOfRawData
        if virtual_size > 0:
            struct.pack_into("<I", unpacked_image, unpacked_section_offset+16, virtual_size)
    
    # Handle LZMA decompression
    if packer_info_array and len(packer_info_array) > 1:
        # Get LZMA properties
        props_info = packer_info_array[0]
        # Use pefile's get_offset_from_rva method to convert RVA to file offset
        props_raw_offset = pe.get_offset_from_rva(props_info.Src)
        
        lzma_props_size = props_info.Dst
        lzma_props_data = packed_pe_data[props_raw_offset:props_raw_offset+lzma_props_size]
        
        if props_raw_offset + lzma_props_size > len(packed_pe_data):
            raise RuntimeError(f"LZMA properties data (RVA {to_hex_string(props_info.Src)} -> Raw {to_hex_string(props_raw_offset)}, "
                              f"Size from Dst {lzma_props_size}) extends beyond packed PE size ({to_hex_string(len(packed_pe_data))}).")
        
        # Standard LZMA properties size is 5 bytes
        if lzma_props_size != LZMA_PROPERTIES_SIZE:
            print(f"Warning: PACKER_INFO[0].Dst (LZMA properties size) is {lzma_props_size}. Standard is {LZMA_PROPERTIES_SIZE}. Using provided size.")
        
        try:
            # Process each LZMA block
            for block_idx in range(1, len(packer_info_array)):
                current_block_info = packer_info_array[block_idx]
                
                compressed_data_rva = current_block_info.Src
                uncompressed_target_rva = current_block_info.Dst
                
                # Use pefile to get file offset
                try:
                    compressed_block_raw_offset = pe.get_offset_from_rva(compressed_data_rva)
                except Exception as e:
                    raise RuntimeError(f"Block {block_idx}: Cannot convert RVA to file offset: {str(e)}")
                
                compressed_data = packed_pe_data[compressed_block_raw_offset:]
                
                if uncompressed_target_rva >= size_of_image:
                    raise RuntimeError(f"Block {block_idx}: PACKER_INFO.Dst (decompression target RVA {to_hex_string(uncompressed_target_rva)}) "
                                      f"exceeds image boundary ({to_hex_string(size_of_image)}).")
                
                # Use Python's lzma module to decompress data
                # Note: We need to construct a properly formatted LZMA stream
                lc = lzma_props_data[0] % 9
                lp = (lzma_props_data[0] // 9) % 5
                pb = lzma_props_data[0] // 45
                dict_size = int.from_bytes(lzma_props_data[1:5], byteorder='little')
                
                # Build LZMA compression filter
                filters = [
                    {
                        "id": lzma.FILTER_LZMA1,
                        "dict_size": dict_size,
                        "lc": lc,
                        "lp": lp,
                        "pb": pb
                    }
                ]
                
                # Create an LZMA decompressor
                decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
                
                # Decompress data
                try:
                    decompressed_data = decompressor.decompress(compressed_data)
                    
                    # Write decompressed data to target location
                    available_space = size_of_image - uncompressed_target_rva
                    if len(decompressed_data) <= available_space:
                        unpacked_image[uncompressed_target_rva:uncompressed_target_rva+len(decompressed_data)] = decompressed_data
                    else:
                        print(f"Warning: Block {block_idx}: Decompressed data size exceeds available space in image")
                        # Only write data that can fit
                        unpacked_image[uncompressed_target_rva:uncompressed_target_rva+available_space] = decompressed_data[:available_space]
                    
                    print(f"Block {block_idx}: Decompressed. Output size={len(decompressed_data)}")
                
                except lzma.LZMAError as e:
                    raise RuntimeError(f"LZMA decompression error: {str(e)}")
        
        except Exception as e:
            raise RuntimeError(f"Error processing LZMA data: {str(e)}")
    
    return bytes(unpacked_image)

def main():
    """Main function processes command line arguments and starts the unpacking process"""
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <packed file> <unpacked file>")
        return 1
    
    packed_filepath = sys.argv[1]
    unpacked_filepath = sys.argv[2]
    
    try:
        # Read packed file
        with open(packed_filepath, 'rb') as f:
            packed_data = f.read()
        
        print(f"Packed file loaded: {packed_filepath}, size: {len(packed_data)} bytes")
        
        # Perform unpacking
        print("Unpacking...")
        unpacked_data = unpack_pe(packed_data)
        
        if unpacked_data:
            print(f"Unpacking function completed. Unpacked size: {len(unpacked_data)} bytes")
            
            # Write unpacked file
            with open(unpacked_filepath, 'wb') as f:
                f.write(unpacked_data)
            
            print(f"Unpacked data written to: {unpacked_filepath}")
            return 0
        else:
            print("Unpacking function failed or produced empty output.")
            return 1
    
    except Exception as e:
        print(f"Exception occurred during unpacking: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())