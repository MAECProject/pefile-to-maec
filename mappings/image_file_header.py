# -*- coding: Latin-1 -*-
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See License.txt for complete terms.

# IMAGE_FILE_HEADER -> CybOX Windows Executable File Object PEFileHeaderType mappings
"""Holds PE File Header information.

pe_struct:      _IMAGE_FILE_HEADER

    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;

pefile_struct:  __IMAGE_FILE_HEADER_format__
cybox_struct:   PEFileHeaderType

"""
IMAGE_FILE_HEADER_MAPPINGS = {'Machine':'headers/file_header/machine',
                              'NumberOfSections':'headers/file_header/number_of_sections',
                              'TimeDateStamp':'headers/file_header/time_date_stamp',
                              'PointerToSymbolTable':'headers/file_header/pointer_to_symbol_table',
                              'NumberOfSymbols':'headers/file_header/number_of_symbols',
                              'SizeOfOptionalHeader':'headers/file_header/size_of_optional_header',
                              'Characteristics':'headers/file_header/characteristics'}

