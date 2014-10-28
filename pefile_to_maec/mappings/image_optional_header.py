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
IMAGE_OPTIONAL_HEADER32_MAPPINGS = {'Magic':'magic',
                                    'MajorLinkerVersion':'major_linker_version',
                                    'MinorLinkerVersion':'minor_linker_version',
                                    'SizeOfCode':'size_of_code',
                                    'SizeOfInitializedData':'size_of_initialized_data',
                                    'SizeOfUninitializedData':'size_of_unintialized_data',
                                    'AddressOfEntryPoint':'address_of_entry_point',
                                    'BaseOfCode':'base_of_code',
                                    'BaseOfData':'base_of_data',
                                    'ImageBase':'image_base',
                                    'SectionAlignment':'section_alignment',
                                    'FileAlignment':'file_alignment',
                                    'MajorOperatingSystemVersion':'major_os_version',
                                    'MinorOperatingSystemVersion':'minor_os_version',
                                    'MajorImageVersion':'major_image_version',
                                    'MinorImageVersion':'minor_image_version',
                                    'MajorSubsystemVersion':'major_subsystem_version',
                                    'MinorSubsystemVersion':'minor_subsystem_version',
                                    'Reserved1':'win32_version_value',
                                    'SizeOfImage':'size_of_image',
                                    'SizeOfHeaders':'size_of_headers',
                                    'CheckSum':'checksum',
                                    'Subsystem':'subsystem',
                                    'DllCharacteristics':'dll_characteristics',
                                    'SizeOfStackReserve':'size_of_stack_reserve',
                                    'SizeOfStackCommit':'size_of_stack_commit',
                                    'SizeOfHeapReserve':'size_of_heap_reserve',
                                    'SizeOfHeapCommit':'size_of_heap_commit',
                                    'LoaderFlags':'loader_flags',
                                    'NumberOfRvaAndSizes':'number_of_rva_and_sizes',
                                    '_IMAGE_DATA_DIRECTORY':'data_directory'}

IMAGE_OPTIONAL_HEADER64_MAPPINGS = {'Magic':'magic',
                                    'MajorLinkerVersion':'major_linker_version',
                                    'MinorLinkerVersion':'minor_linker_version',
                                    'SizeOfCode':'size_of_code',
                                    'SizeOfInitializedData':'size_of_initialized_data',
                                    'SizeOfUninitializedData':'size_of_unintialized_data',
                                    'AddressOfEntryPoint':'address_of_entry_point',
                                    'BaseOfCode':'base_of_code',
                                    'BaseOfData':'base_of_data',
                                    'ImageBase':'image_base',
                                    'SectionAlignment':'section_alignment',
                                    'FileAlignment':'file_alignment',
                                    'MajorOperatingSystemVersion':'major_os_version',
                                    'MinorOperatingSystemVersion':'minor_os_version',
                                    'MajorImageVersion':'major_image_version',
                                    'MinorImageVersion':'minor_image_version',
                                    'MajorSubsystemVersion':'major_subsystem_version',
                                    'MinorSubsystemVersion':'minor_subsystem_version',
                                    'Reserved1':'win32_version_value',
                                    'SizeOfImage':'size_of_image',
                                    'SizeOfHeaders':'size_of_headers',
                                    'CheckSum':'checksum',
                                    'Subsystem':'subsystem',
                                    'DllCharacteristics':'dll_characteristics',
                                    'SizeOfStackReserve':'size_of_stack_reserve',
                                    'SizeOfStackCommit':'size_of_stack_commit',
                                    'SizeOfHeapReserve':'size_of_heap_reserve',
                                    'SizeOfHeapCommit':'size_of_heap_commit',
                                    'LoaderFlags':'loader_flags',
                                    'NumberOfRvaAndSizes':'number_of_rva_and_sizes',
                                    '_IMAGE_DATA_DIRECTORY':'data_directory'}

