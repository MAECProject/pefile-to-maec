# -*- coding: Latin-1 -*-
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See License.txt for complete terms.

# __IMAGE_IMPORT_DESCRIPTOR__format__ -> CybOX Windows Executable File Object Imports mappings
IMAGE_IMPORT_DESCRIPTOR_MAPPINGS = {'OriginalFirstThunk':'No_Mapping',
                                    'TimeDateStamp':'No_Mapping',
                                    'ForwarderChain':'No_Mapping',
                                    'Name':'imports/file_name',
                                    'FirstThunk':'imports/virtual_address'}

# __IMAGE_THUNK_DATA_format__ -> CybOX Windows Executable File Object Imports mappings
IMAGE_THUNK_DATA32_MAPPINGS = {'ForwarderString':'No_Mapping',
                               'Function':'imports/imported_functions/virtual_address',
                               'Ordinal':'imports/imported_functions/ordinal',
                               'AddressOfData':'No_Mapping'}

# __IMAGE_THUNK_DATA64_format__ -> CybOX Windows Executable File Object Imports mappings
IMAGE_THUNK_DATA64_MAPPINGS = {'ForwarderString':'No_Mapping',
                               'Function':'imports/imported_functions/virtual_address',
                               'Ordinal':'imports/imported_functions/ordinal',
                               'AddressOfData':'No_Mapping'}

# IMAGE_IMPORT_BY_NAME -> CybOX Windows Executable File Object Imports mappings
IMAGE_IMPORT_BY_NAME_MAPPINGS = {'Hint':'imports/imported_functions/hint',
                                 'Name':'imports/imported_functions/function_name'}

# __IMAGE_BOUND_IMPORT_DESCRIPTOR_format__ -> CybOX Windows Executable File Object Bound Imports mappings
IMAGE_BOUND_IMPORT_DESCRIPTOR_MAPPINGS = {'TimeDateStamp':'No_Mapping',
                                          'OffsetModuleName':'No_Mapping',
                                          'NumberOfModuleForwarderRefs':'No_Mapping'}

# __IMAGE_BOUND_IMPORT_FORWARDER_REF -> CybOX Windows Executable File Object Bound Imports mappings
IMAGE_BOUND_IMPORT_FORWARDER_REF_MAPPINGS = {'TimeDateStamp':'No_Mapping',
                                             'OffsetModuleName':'No_Mapping',
                                             'Reserved':'No_Mapping'}

