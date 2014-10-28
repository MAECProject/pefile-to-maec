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
IMAGE_FILE_HEADER_MAPPINGS = {'Machine':'machine',
                              'NumberOfSections':'number_of_sections',
                              'TimeDateStamp':'time_date_stamp',
                              'PointerToSymbolTable':'pointer_to_symbol_table',
                              'NumberOfSymbols':'number_of_symbols',
                              'SizeOfOptionalHeader':'size_of_optional_header',
                              'Characteristics':'characteristics'}

