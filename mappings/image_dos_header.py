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
IMAGE_DOS_HEADER_MAPPINGS = {'e_magic':'e_magic',
                             'e_cblp':'e_cblp',
                             'e_cp':'e_cp',
                             'e_crlc':'e_crlc',
                             'e_cparhdr':'e_cparhdr',
                             'e_minalloc':'e_minalloc',
                             'e_maxalloc':'e_maxalloc',
                             'e_ss':'e_ss',
                             'e_sp':'e_sp',
                             'e_csum':'e_csum',
                             'e_ip':'e_ip',
                             'e_cs':'e_cs',
                             'e_lfarlc':'e_lfarlc',
                             'e_ovno':'e_ovro',
                             'e_res':'e_res',
                             'e_oemid':'e_oemid',
                             'e_oeminfo':'e_oeminfo',
                             'e_res2':'reserved2',
                             'e_lfanew':'e_lfanew'}

