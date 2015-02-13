# -*- coding: Latin-1 -*-
# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See License.txt for complete terms.

# __IMAGE_EXPORT_DIRECTORY_format__ -> CybOX Windows Executable File Object Exports mappings
IMAGE_EXPORT_DIRECTORY_MAPPINGS = {'Characteristics':'No_Mapping',
                                   'TimeDateStamp':'exports/exports_time_stamp',
                                   'MajorVersion':'No_Mapping',
                                   'MinorVersion':'No_Mapping',
                                   'Name':'exports/name',
                                   'Base':'headers/optional_header/image_base',
                                   'NumberOfFunctions':'exports/number_of_functions',
                                   'NumberOfNames':'exports/number_of_names',
                                   'AddressOfFunctions':'No_Mapping',                               # RVA from base of image
                                   'AddressOfNames':'No_Mapping',                                   # RVA from base of image
                                   'AddressOfNameOrdinals':'No_Mapping'}                            # RVA from base of image
