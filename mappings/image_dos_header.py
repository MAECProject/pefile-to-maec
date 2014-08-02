# -*- coding: Latin-1 -*-
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See License.txt for complete terms.

# IMAGE_DOS_HEADER -> CybOX Windows Executable File Object DOSHeaderType mappings
"""Holds DOS Header information.

pe_struct:          _IMAGE_DOS_HEADER

    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header

pefile_struct:      __IMAGE_DOS_HEADER_format__
cybox_struct:       DOSHeaderType

"""
IMAGE_DOS_HEADER_MAPPINGS = {'e_magic':'headers/dos_header/e_magic',
                             'e_cblp':'headers/dos_header/e_cblp',
                             'e_cp':'headers/dos_header/e_cp',
                             'e_crlc':'headers/dos_header/e_crlc',
                             'e_cparhdr':'headers/dos_header/e_cparhdr',
                             'e_minalloc':'headers/dos_header/e_minalloc',
                             'e_maxalloc':'headers/dos_header/e_maxalloc',
                             'e_ss':'headers/dos_header/e_ss',
                             'e_sp':'headers/dos_header/e_sp',
                             'e_csum':'headers/dos_header/e_csum',
                             'e_ip':'headers/dos_header/e_ip',
                             'e_cs':'headers/dos_header/e_cs',
                             'e_lfarlc':'headers/dos_header/e_lfarlc',
                             'e_ovno':'headers/dos_header/e_ovro',
                             'e_res':'headers/dos_header/e_res',
                             'e_oemid':'headers/dos_header/e_oemid',
                             'e_oeminfo':'headers/dos_header/e_oeminfo',
                             'e_res2':'headers/dos_header/reserved2',
                             'e_lfanew':'headers/dos_header/e_lfanew'}

