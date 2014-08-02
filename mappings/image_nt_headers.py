# -*- coding: Latin-1 -*-
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See License.txt for complete terms.

# IMAGE_NT_HEADERS -> CybOX Windows Executable File Object PEHeadersType mappings
"""Holds NT Headers information.

pe_struct:          _IMAGE_NT_HEADERS

    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;

pefile_struct:      __IMAGE_NT_HEADERS_format__
cybox_struct:       PEHeadersType

"""
IMAGE_NT_HEADERS_MAPPINGS = {'Signature':'headers/signature'}
IMAGE_NT_HEADERS64_MAPPINGS = {'Signature':'headers/signature'}

