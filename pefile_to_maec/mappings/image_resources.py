# -*- coding: Latin-1 -*-
# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See License.txt for complete terms.

# __IMAGE_RESOURCE_DIRECTORY_format__ -> CybOX Windows Executable File Object Resource Table mappings
IMAGE_RESOURCE_DIRECTORY_MAPPINGS = {'Characteristics':'No_Mapping',
                                     'TimeDateStamp':'No_Mapping',
                                     'MajorVersion':'No_Mapping',
                                     'MinorVersion':'No_Mapping',
                                     'NumberOfNamedEntries':'No_Mapping',
                                     'NumberOfIdEntries':'No_Mapping'}

# __IMAGE_RESOURCE_DIRECTORY_ENTRY_format__ -> CybOX Windows Executable File Object Resource Entry mappings
IMAGE_RESOURCE_DIRECTORY_ENTRY_MAPPINGS = {'Name':'resources/name',
                                           'OffsetToData':'resources/virtual_address'}

# __IMAGE_RESOURCE_DATA_ENTRY_format__ -> CybOX Windows Executable File Object Resource Table mappings
IMAGE_RESOURCE_DATA_ENTRY_MAPPINGS = {'OffsetToData':'resources/virtual_address',
                                      'Size':'resources/size',
                                      'CodePage':'No_Mapping',
                                      'Reserved':'No_Mapping'}
        
