// Build: g++ -o vmpunpacker.exe vmpunpacker.cpp lzma/LzmaDecode.cpp -I./lzma -std=c++17

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <algorithm> // For std::copy, std::fill
#include <cstring>   // For memcpy, memset, strnlen
#include <iostream>
#include <fstream>
#include <limits>
#include <string>
#include <sstream>   // For ostringstream in error messages
#include <memory>    // For std::unique_ptr

#include "LzmaDecode.h" // Assuming this provides CLzmaDecoderState, LzmaDecodeProperties, LzmaGetNumProbs, LzmaDecode, CProb, LZMA_PROPERTIES_SIZE, LZMA_RESULT_OK

// Define PACKER_INFO structure
struct PACKER_INFO {
    uint32_t Src;
    uint32_t Dst;
};

// Helper to convert values to hex string for error messages
template <typename T>
static std::string ToHexString(T val, bool prefix = true) {
    std::ostringstream oss;
    if (prefix) oss << "0x";
    oss << std::hex << val;
    return oss.str();
}

static DWORD RVAtoRawOffset(DWORD rva, const IMAGE_NT_HEADERS* nt_headers, const BYTE* file_buffer_start, size_t file_buffer_size, const char* context_info = "") {
    const IMAGE_SECTION_HEADER* section_header_array = IMAGE_FIRST_SECTION(nt_headers);
    WORD num_sections = nt_headers->FileHeader.NumberOfSections;

    if (rva < nt_headers->OptionalHeader.SizeOfHeaders) {
        if (rva >= file_buffer_size) {
            std::ostringstream err_oss;
            err_oss << "RVAtoRawOffset Error (" << context_info << "): Header RVA " << ToHexString(rva) 
                    << " is out of file buffer bounds (" << ToHexString(file_buffer_size) << ").";
            throw std::runtime_error(err_oss.str());
        }
        return rva;
    }

    for (WORD i = 0; i < num_sections; ++i) {
        const IMAGE_SECTION_HEADER& current_section = section_header_array[i];
        if (rva >= current_section.VirtualAddress &&
            rva < current_section.VirtualAddress + current_section.Misc.VirtualSize) {
            
            if (current_section.PointerToRawData != 0) {
                DWORD offset_in_section_virtual = rva - current_section.VirtualAddress;
                if (offset_in_section_virtual < current_section.SizeOfRawData) {
                    DWORD raw_offset = current_section.PointerToRawData + offset_in_section_virtual;
                    if (raw_offset >= file_buffer_size) {
                         std::ostringstream err_oss;
                         err_oss << "RVAtoRawOffset Error (" << context_info << "): Calculated raw offset " << ToHexString(raw_offset)
                                 << " for RVA " << ToHexString(rva) << " in section '" 
                                 << std::string(reinterpret_cast<const char*>(current_section.Name), strnlen(reinterpret_cast<const char*>(current_section.Name), 8))
                                 << "' is out of file buffer bounds (" << ToHexString(file_buffer_size) << ").";
                         throw std::runtime_error(err_oss.str());
                    }
                    return raw_offset;
                } else {
                    std::ostringstream err_oss;
                    err_oss << "RVAtoRawOffset Error (" << context_info << "): RVA " << ToHexString(rva) 
                            << " is in virtual-only part of section '" 
                            << std::string(reinterpret_cast<const char*>(current_section.Name), strnlen(reinterpret_cast<const char*>(current_section.Name), 8)) << "'.";
                    throw std::runtime_error(err_oss.str());
                }
            } else {
                std::ostringstream err_oss;
                err_oss << "RVAtoRawOffset Error (" << context_info << "): RVA " << ToHexString(rva) 
                        << " is in section '" 
                        << std::string(reinterpret_cast<const char*>(current_section.Name), strnlen(reinterpret_cast<const char*>(current_section.Name), 8))
                        << "' which has no raw data (PointerToRawData is 0).";
                throw std::runtime_error(err_oss.str());
            }
        }
    }

    std::ostringstream err_oss;
    err_oss << "RVAtoRawOffset Error (" << context_info << "): RVA " << ToHexString(rva) << " not found in PE headers or any section.";
    throw std::runtime_error(err_oss.str());
}

static const BYTE* FindPattern(const BYTE* data, size_t data_len, const BYTE* pattern, size_t pattern_len) {
    if (pattern_len == 0 || data_len < pattern_len) return nullptr;
    for (size_t i = 0; i <= data_len - pattern_len; ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern_len; ++j) {
            if (pattern[j] != 0xFF && data[i + j] != pattern[j]) { // 0xFF as wildcard
                match = false;
                break;
            }
        }
        if (match) {
            return data + i;
        }
    }
    return nullptr;
}

std::vector<BYTE> UnpackPE(const BYTE* packed_pe_data_const, size_t packed_pe_size) {
    if (!packed_pe_data_const || packed_pe_size == 0) {
        throw std::runtime_error("Packed PE data is null or empty.");
    }

    // Create a mutable copy to work with for headers
    std::vector<BYTE> packed_pe_buffer(packed_pe_data_const, packed_pe_data_const + packed_pe_size);
    BYTE* packed_data = packed_pe_buffer.data(); // Non-const pointer to the buffer data

    IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(packed_data);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        throw std::runtime_error("Invalid DOS signature");
    }
    if (static_cast<size_t>(dos_header->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > packed_pe_size) {
        throw std::runtime_error("NT headers offset out of bounds.");
    }
    IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(packed_data + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        throw std::runtime_error("Invalid NT signature");
    }

    DWORD size_of_image = nt_headers->OptionalHeader.SizeOfImage;
    DWORD size_of_headers = nt_headers->OptionalHeader.SizeOfHeaders;
    WORD num_sections = nt_headers->FileHeader.NumberOfSections;

    if (size_of_headers > packed_pe_size || size_of_headers > size_of_image) {
        throw std::runtime_error("Invalid SizeOfHeaders.");
    }

    std::vector<BYTE> unpacked_image(size_of_image); // Automatically zero-initialized

    // Copy PE headers
    std::copy(packed_data, packed_data + size_of_headers, unpacked_image.begin());

    IMAGE_NT_HEADERS* nt_headers_unpacked = reinterpret_cast<IMAGE_NT_HEADERS*>(unpacked_image.data() + dos_header->e_lfanew);
    IMAGE_SECTION_HEADER* sections_unpacked = IMAGE_FIRST_SECTION(nt_headers_unpacked);
    const IMAGE_SECTION_HEADER* sections_original = IMAGE_FIRST_SECTION(nt_headers);

    // Collect RVA patterns to find PACKER_INFO array
    std::vector<uint64_t> rva_patterns_array;
    for (WORD i = 0; i < num_sections; ++i) {
        if (reinterpret_cast<const BYTE*>(&sections_original[i+1]) > packed_data + packed_pe_size) {
             throw std::runtime_error("Section header data out of bounds during RVA pattern collection.");
        }
        bool condition1 = (sections_original[i].SizeOfRawData == 0);
        bool condition2 = (sections_original[i].PointerToRawData == 0);
        bool condition3 = !(sections_original[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA);

        if (condition1 && condition2 && condition3) {
            rva_patterns_array.push_back((static_cast<uint64_t>(sections_original[i].VirtualAddress) << 32) | 0xFFFFFFFFULL);
        }
    }
    
    const BYTE* match_in_packed_pe_pattern_start = nullptr;
    size_t rva_patterns_bytes_len = rva_patterns_array.size() * sizeof(uint64_t);

    if (rva_patterns_bytes_len > 0) {
         match_in_packed_pe_pattern_start = FindPattern(packed_data, packed_pe_size, 
                                                        reinterpret_cast<const BYTE*>(rva_patterns_array.data()), 
                                                        rva_patterns_bytes_len);
    }

    PACKER_INFO* packer_info_array_ptr = nullptr;
    size_t num_packer_entries = 0;

    if (match_in_packed_pe_pattern_start) {
        // PACKER_INFO array is located just before the matched pattern sequence
        if (match_in_packed_pe_pattern_start < packed_data + sizeof(PACKER_INFO)) {
            throw std::runtime_error("Located RVA pattern is too close to the beginning of the file to precede PACKER_INFO[0].");
        }
        packer_info_array_ptr = reinterpret_cast<PACKER_INFO*>(const_cast<BYTE*>(match_in_packed_pe_pattern_start) - sizeof(PACKER_INFO));
        num_packer_entries = rva_patterns_array.size(); 

        // Validate that reading this array won't go out of bounds of the packed_pe_buffer
        if (num_packer_entries > 0) {
            const BYTE* end_of_packer_info_array = reinterpret_cast<const BYTE*>(packer_info_array_ptr) + num_packer_entries * sizeof(PACKER_INFO);
            if (end_of_packer_info_array > packed_data + packed_pe_size || reinterpret_cast<const BYTE*>(packer_info_array_ptr) < packed_data) {
                 throw std::runtime_error("Located PACKER_INFO array extends beyond packed PE buffer or has invalid start.");
            }
        }
    } else if (!rva_patterns_array.empty()) {
         throw std::runtime_error("RVA pattern sequence for PACKER_INFO not found in packed PE, but patterns were expected.");
    } else {
        std::cout << "Warning: RVA pattern array is empty. No PACKER_INFO entries to process for LZMA." << std::endl;
    }

    // Copy section data and update section headers in the unpacked image
    for (WORD i = 0; i < num_sections; ++i) {
        const IMAGE_SECTION_HEADER& original_sh = sections_original[i];
        IMAGE_SECTION_HEADER& unpacked_sh = sections_unpacked[i];
        
        unpacked_sh = original_sh; // Copy original section header

        if (original_sh.PointerToRawData != 0 && original_sh.SizeOfRawData > 0) {
             if (original_sh.PointerToRawData + original_sh.SizeOfRawData <= packed_pe_size &&
                 original_sh.VirtualAddress + original_sh.SizeOfRawData <= size_of_image) {
                std::copy(packed_data + original_sh.PointerToRawData,
                          packed_data + original_sh.PointerToRawData + original_sh.SizeOfRawData,
                          unpacked_image.begin() + original_sh.VirtualAddress);
            } else {
                 std::cerr << "Warning: Section " << std::string(reinterpret_cast<const char*>(original_sh.Name), strnlen(reinterpret_cast<const char*>(original_sh.Name), 8)) 
                           << " data out of bounds. RawOffset=" << ToHexString(original_sh.PointerToRawData) << ", RawSize=" << ToHexString(original_sh.SizeOfRawData)
                           << ", VA=" << ToHexString(original_sh.VirtualAddress) << ". Skipping copy." << std::endl;
            }
        }
        // Update PointerToRawData and SizeOfRawData for the unpacked file
        unpacked_sh.PointerToRawData = original_sh.VirtualAddress; // Common practice for unpacked files
        if (unpacked_sh.Misc.VirtualSize > 0) { // If VirtualSize is non-zero, use it for SizeOfRawData
             unpacked_sh.SizeOfRawData = unpacked_sh.Misc.VirtualSize;
        } else { // If VirtualSize is zero, SizeOfRawData should also be zero (or reflect actual copied data if any)
             unpacked_sh.SizeOfRawData = original_sh.SizeOfRawData; // Fallback or keep as original if no better logic
        }
    }
    
    if (packer_info_array_ptr && num_packer_entries > 0) {
        CLzmaDecoderState lzma_state = { 0 };
        std::unique_ptr<CProb[]> lzma_probs_holder; // RAII for lzma_state.Probs

        // Get LZMA properties from the first PACKER_INFO entry
        const PACKER_INFO& props_info = packer_info_array_ptr[0];
        DWORD props_raw_offset = RVAtoRawOffset(props_info.Src, nt_headers, packed_data, packed_pe_size, "LZMA Props");
        
        const BYTE* lzma_props_data_ptr = packed_data + props_raw_offset;
        unsigned int lzma_props_data_size = props_info.Dst; // Size of props from Dst

        if (props_raw_offset + lzma_props_data_size > packed_pe_size) {
            std::ostringstream err_oss;
            err_oss << "LZMA properties data (RVA " << ToHexString(props_info.Src) << " -> Raw " << ToHexString(props_raw_offset) 
                    << ", Size from Dst " << lzma_props_data_size << ") extends beyond packed PE size (" << ToHexString(packed_pe_size) << ").";
            throw std::runtime_error(err_oss.str());
        }
        
        if (lzma_props_data_size != LZMA_PROPERTIES_SIZE) {
             std::cout << "Warning: PACKER_INFO[0].Dst (LZMA props size) is " << lzma_props_data_size
                       << ". Standard is " << LZMA_PROPERTIES_SIZE << ". Using provided size." << std::endl;
        }

        if (LzmaDecodeProperties(&lzma_state.Properties, lzma_props_data_ptr, lzma_props_data_size) != LZMA_RESULT_OK) {
            std::ostringstream err_oss;
            err_oss << "LzmaDecodeProperties failed for props at RVA " << ToHexString(props_info.Src) 
                    << " (Raw " << ToHexString(props_raw_offset) << ") with size " << lzma_props_data_size << ".";
            throw std::runtime_error(err_oss.str());
        }

        size_t num_probs = LzmaGetNumProbs(&lzma_state.Properties);
        if (num_probs > 0) { // Allocate only if needed
            lzma_probs_holder = std::make_unique<CProb[]>(num_probs);
            lzma_state.Probs = lzma_probs_holder.get();
            // LzmaDec_Init(&lzma_state); // Often needed to initialize probs table, check LzmaDecode.h if it does this or expects pre-init
        }


        for (size_t block_idx = 1; block_idx <= num_packer_entries; ++block_idx) {
            const PACKER_INFO& current_block_info = packer_info_array_ptr[block_idx];
            
            uint32_t compressed_data_rva = current_block_info.Src;
            uint32_t uncompressed_target_rva = current_block_info.Dst;

            std::string context_str_stream = "Block " + std::to_string(block_idx) + " Compressed Data";
            DWORD compressed_block_raw_offset = RVAtoRawOffset(compressed_data_rva, nt_headers, packed_data, packed_pe_size, context_str_stream.c_str());

            const BYTE* compressed_stream_ptr = packed_data + compressed_block_raw_offset;
            
            if (uncompressed_target_rva >= size_of_image) {
                 std::ostringstream err_oss;
                 err_oss << "Block " << block_idx << ": PACKER_INFO.Dst (uncompressed target RVA " << ToHexString(uncompressed_target_rva) 
                         << ") is out of image bounds (" << ToHexString(size_of_image) << ").";
                 throw std::runtime_error(err_oss.str());
            }
            BYTE* uncomp_target_ptr_in_unpacked = unpacked_image.data() + uncompressed_target_rva;
            
            SizeT inProcessed = 0, outProcessed = 0;
            SizeT inSize = static_cast<SizeT>(-1); // LzmaDecode determines actual size
            SizeT outSizeLimit = static_cast<SizeT>(-1); // LzmaDecode determines actual size

            // Ensure the target buffer for decompression is valid and within bounds
            // Calculate max possible output based on remaining space in unpacked_image
            if (uncompressed_target_rva < size_of_image) {
                SizeT available_out_space = size_of_image - uncompressed_target_rva;
                // If outSizeLimit is -1, LzmaDecode might write past available_out_space if not careful.
                // The original C code implies LzmaDecode handles this, but it's safer to provide a limit if possible.
                // However, sticking to -1 as per original analysis of loader_part.cc
            } else {
                 std::ostringstream err_oss;
                 err_oss << "Block " << block_idx << ": Decompression target RVA " << ToHexString(uncompressed_target_rva) << " is invalid.";
                 throw std::runtime_error(err_oss.str());
            }
            
            // Calculate max possible input based on remaining space in packed_data
            SizeT available_in_space = packed_pe_size - compressed_block_raw_offset;
            // If inSize is -1, LzmaDecode reads until EOS or error.
            // Ensure compressed_stream_ptr is valid.

            int lzma_res = LzmaDecode(&lzma_state,
                                      compressed_stream_ptr,
                                      inSize, 
                                      &inProcessed,
                                      uncomp_target_ptr_in_unpacked,
                                      outSizeLimit,
                                      &outProcessed);

            if (lzma_res != LZMA_RESULT_OK) {
                std::ostringstream err_oss;
                err_oss << "LzmaDecode failed for block " << block_idx << " (SrcRVA " << ToHexString(compressed_data_rva) 
                        << " -> Raw " << ToHexString(compressed_block_raw_offset) << ", DstRVA " << ToHexString(uncompressed_target_rva) 
                        << ") with error " << lzma_res << ". InProcessed=" << inProcessed << ", OutProcessed=" << outProcessed;
                throw std::runtime_error(err_oss.str());
            }
            // std::cout << "Block " << block_idx << ": Decompressed. InProcessed=" << inProcessed << ", OutProcessed=" << outProcessed << std::endl;
        }
    }
    return unpacked_image;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <packed_file> <unpacked_file>\n";
        return 1;
    }

    const char* packed_filepath = argv[1];
    const char* unpacked_filepath = argv[2];

    std::ifstream f_packed(packed_filepath, std::ios::binary | std::ios::ate);
    if (!f_packed) {
        std::cerr << "Error opening packed file: " << packed_filepath << std::endl;
        return 1;
    }

    std::streamsize packed_file_size_s = f_packed.tellg();
    if (packed_file_size_s <= 0) {
        std::cerr << "Packed file is empty or invalid size." << std::endl;
        return 1;
    }
    f_packed.seekg(0, std::ios::beg);
    
    size_t packed_file_len = static_cast<size_t>(packed_file_size_s);
    std::vector<BYTE> packed_buffer_vec(packed_file_len);

    if (!f_packed.read(reinterpret_cast<char*>(packed_buffer_vec.data()), packed_file_len)) {
        std::cerr << "Failed to read packed file." << std::endl;
        return 1;
    }
    f_packed.close();

    std::cout << "Packed file loaded: " << packed_filepath << ", Size: " << packed_file_len << " bytes\n";

    try {
        std::cout << "Unpacking...\n";
        std::vector<BYTE> unpacked_data_vec = UnpackPE(packed_buffer_vec.data(), packed_buffer_vec.size());

        if (!unpacked_data_vec.empty()) {
            std::cout << "Unpacker function finished. Unpacked size: " << unpacked_data_vec.size() << " bytes\n";
            std::ofstream f_unpacked(unpacked_filepath, std::ios::binary);
            if (!f_unpacked) {
                std::cerr << "Error opening output file for unpacked data: " << unpacked_filepath << std::endl;
                return 1;
            }
            f_unpacked.write(reinterpret_cast<const char*>(unpacked_data_vec.data()), unpacked_data_vec.size());
            std::cout << "Unpacked data written to: " << unpacked_filepath << std::endl;
        } else {
            std::cerr << "Unpacker function failed or produced empty output.\n";
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception during Unpacking: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
