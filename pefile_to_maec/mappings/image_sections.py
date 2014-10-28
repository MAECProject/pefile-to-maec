# -*- coding: Latin-1 -*-
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See License.txt for complete terms.

# IMAGE_SECTION_HEADER -> CybOX Windows Executable File Object Section Header Struct mappings
IMAGE_SECTION_HEADER_MAPPINGS = {'Name':'section_header/name',
                                 'Misc_VirtualSize':'section_header/virtual_size',
                                 'VirtualAddress':'section_header/virtual_address',
                                 'SizeOfRawData':'section_header/size_of_raw_data',
                                 'PointerToRawData':'section_header/pointer_to_raw_data',
                                 'PointerToRelocations':'section_header/pointer_to_relocations',
                                 'PointerToLinenumbers':'section_header/pointer_to_linenumbers',
                                 'NumberOfRelocations':'section_header/number_of_relocations',
                                 'NumberOfLinenumbers':'section_header/number_of_linenumbers',
                                 'Characteristics':'section_header/characteristics'}
