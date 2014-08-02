# -*- coding: Latin-1 -*-
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See License.txt for complete terms.

# IMAGE_OPTIONAL_HEADERS -> CybOX Windows Executable File Object PEOptionalHeaderType mappings
"""Holds Optional Header information.

pe_struct:      _IMAGE_OPTIONAL_HEADERS
    //
    // Standard fields.
    //

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    //
    // NT additional fields.
    //

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];

pefile_struct:  __IMAGE_OPTIONAL_HEADERS_format__
cybox_struct:   PEOptionalHeader

"""
IMAGE_OPTIONAL_HEADER32_MAPPINGS = {'Magic':'headers/optional_header/magic',
                                    'MajorLinkerVersion':'headers/optional_header/major_linker_version',
                                    'MinorLinkerVersion':'headers/optional_header/minor_linker_version',
                                    'SizeOfCode':'headers/optional_header/size_of_code',
                                    'SizeOfInitializedData':'headers/optional_header/size_of_initialized_data',
                                    'SizeOfUninitializedData':'headers/optional_header/size_of_unintialized_data',
                                    'AddressOfEntryPoint':'headers/optional_header/address_of_entry_point',
                                    'BaseOfCode':'headers/optional_header/base_of_code',
                                    'BaseOfData':'headers/optional_header/base_of_data',
                                    'ImageBase':'headers/optional_header/image_base',
                                    'SectionAlignment':'headers/optional_header/section_alignment',
                                    'FileAlignment':'headers/optional_header/file_alignment',
                                    'MajorOperatingSystemVersion':'headers/optional_header/major_os_version',
                                    'MinorOperatingSystemVersion':'headers/optional_header/minor_os_version',
                                    'MajorImageVersion':'headers/optional_header/major_image_version',
                                    'MinorImageVersion':'headers/optional_header/minor_image_version',
                                    'MajorSubsystemVersion':'headers/optional_header/major_subsystem_version',
                                    'MinorSubsystemVersion':'headers/optional_header/minor_subsystem_version',
                                    'Reserved1':'headers/optional_header/win32_version_value',
                                    'SizeOfImage':'headers/optional_header/size_of_image',
                                    'SizeOfHeaders':'headers/optional_header/size_of_headers',
                                    'CheckSum':'headers/optional_header/checksum',
                                    'Subsystem':'headers/optional_header/subsystem',
                                    'DllCharacteristics':'headers/optional_header/dll_characteristics',
                                    'SizeOfStackReserve':'headers/optional_header/size_of_stack_reserve',
                                    'SizeOfStackCommit':'headers/optional_header/size_of_stack_commit',
                                    'SizeOfHeapReserve':'headers/optional_header/size_of_heap_reserve',
                                    'SizeOfHeapCommit':'headers/optional_header/size_of_heap_commit',
                                    'LoaderFlags':'headers/optional_header/loader_flags',
                                    'NumberOfRvaAndSizes':'headers/optional_header/number_of_rva_and_sizes',
                                    '_IMAGE_DATA_DIRECTORY':'headers/optional_header/data_directory'}

IMAGE_OPTIONAL_HEADER64_MAPPINGS = {'Magic':'headers/optional_header/magic',
                                    'MajorLinkerVersion':'headers/optional_header/major_linker_version',
                                    'MinorLinkerVersion':'headers/optional_header/minor_linker_version',
                                    'SizeOfCode':'headers/optional_header/size_of_code',
                                    'SizeOfInitializedData':'headers/optional_header/size_of_initialized_data',
                                    'SizeOfUninitializedData':'headers/optional_header/size_of_unintialized_data',
                                    'AddressOfEntryPoint':'headers/optional_header/address_of_entry_point',
                                    'BaseOfCode':'headers/optional_header/base_of_code',
                                    'BaseOfData':'headers/optional_header/base_of_data',
                                    'ImageBase':'headers/optional_header/image_base',
                                    'SectionAlignment':'headers/optional_header/section_alignment',
                                    'FileAlignment':'headers/optional_header/file_alignment',
                                    'MajorOperatingSystemVersion':'headers/optional_header/major_os_version',
                                    'MinorOperatingSystemVersion':'headers/optional_header/minor_os_version',
                                    'MajorImageVersion':'headers/optional_header/major_image_version',
                                    'MinorImageVersion':'headers/optional_header/minor_image_version',
                                    'MajorSubsystemVersion':'headers/optional_header/major_subsystem_version',
                                    'MinorSubsystemVersion':'headers/optional_header/minor_subsystem_version',
                                    'Reserved1':'headers/optional_header/win32_version_value',
                                    'SizeOfImage':'headers/optional_header/size_of_image',
                                    'SizeOfHeaders':'headers/optional_header/size_of_headers',
                                    'CheckSum':'headers/optional_header/checksum',
                                    'Subsystem':'headers/optional_header/subsystem',
                                    'DllCharacteristics':'headers/optional_header/dll_characteristics',
                                    'SizeOfStackReserve':'headers/optional_header/size_of_stack_reserve',
                                    'SizeOfStackCommit':'headers/optional_header/size_of_stack_commit',
                                    'SizeOfHeapReserve':'headers/optional_header/size_of_heap_reserve',
                                    'SizeOfHeapCommit':'headers/optional_header/size_of_heap_commit',
                                    'LoaderFlags':'headers/optional_header/loader_flags',
                                    'NumberOfRvaAndSizes':'headers/optional_header/number_of_rva_and_sizes',
                                    '_IMAGE_DATA_DIRECTORY':'headers/optional_header/data_directory'}

