# -*- coding: Latin-1 -*-
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See License.txt for complete terms.

# IMAGE_DATA_DIRECTORY_ -> CybOX Windows Executable File Object Data Directory DataDirectoryStruct mappings
"""Represents an array of data directory structures containing the RVA and size of the actual object.

pe_struct:  _IMAGE_DATA_DIRECTORY

    DWORD   VirtualAddress;
    DWORD   Size;

pefile_struct:  __IMAGE_DATA_DIRECTORY_format__
cybox_struct:   DataDirectoryStructType

"""
IMAGE_DATA_DIRECTORY_MAPPINGS = {'VirtualAddress':'headers/optional_header/data_directory/virtual_address',
                                 'Size':'headers/optional_header/data_directory/size'}

# __IMAGE_DATA_DIRECTORY_ENTRY_format__ -> CybOX Windows Executable File Object Data Directory mappings
"""Each IMAGE_DATA_DIRECTORY_ENTRY is of IMAGE_DATA_DIRECTORY type.

    // Directory Entries

    #define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
    #define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
    #define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
    #define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
    #define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
    #define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
    #define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
    //      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
    #define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
    #define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
    #define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
    #define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
    #define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
    #define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
    #define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
    #define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

"""
IMAGE_DATA_DIRECTORY_ENTRY_MAPPINGS = {'IMAGE_DIRECTORY_ENTRY_EXPORT':'headers/optional_header/data_directory/export_table',
                                       'IMAGE_DIRECTORY_ENTRY_IMPORT':'headers/optional_header/data_directory/import_table',
                                       'IMAGE_DIRECTORY_ENTRY_RESOURCE':'headers/optional_header/data_directory/resource_table',
                                       'IMAGE_DIRECTORY_ENTRY_EXCEPTION':'headers/optional_header/data_directory/exception_table',
                                       'IMAGE_DIRECTORY_ENTRY_SECURITY':'headers/optional_header/data_directory/certificate_table',
                                       'IMAGE_DIRECTORY_ENTRY_BASERELOC':'headers/optional_header/data_directory/base_relocation_table',
                                       'IMAGE_DIRECTORY_ENTRY_DEBUG':'headers/optional_header/data_directory/debug',
                                       'IMAGE_DIRECTORY_ENTRY_COPYRIGHT':'headers/optional_header/data_directory/architecture',
                                       'IMAGE_DIRECTORY_ENTRY_GLOBALPTR':'headers/optional_header/data_directory/global_ptr',
                                       'IMAGE_DIRECTORY_ENTRY_TLS':'headers/optional_header/data_directory/tls_table',
                                       'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG':'headers/optional_header/data_directory/load_config',
                                       'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT':'headers/optional_header/data_directory/bound_import',
                                       'IMAGE_DIRECTORY_ENTRY_IAT':'headers/optional_header/data_directory/import_address_table',
                                       'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT':'headers/optional_header/data_directory/delay_import_descriptor',
                                       'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR':'headers/optional_header/data_directory/clr_runtime_header',
                                       'IMAGE_DIRECTORY_ENTRY_RESERVED':'headers/optional_header/data_directory/reserved'}

# __IMAGE_DIRECTORY_ENTRY_EXPORT_format__ -> CybOX Windows Executable File Object Data Directory Export Table mappings
IMAGE_DIRECTORY_ENTRY_EXPORT_MAPPINGS = {'VirtualAddress':'headers/optional_header/data_directory/export_table/virtual_address',
                                         'Size':'headers/optional_header/data_directory/export_table/size'}

# __IMAGE_DIRECTORY_ENTRY_IMPORT_format__ -> CybOX Windows Executable File Object Data Directory Import Table mappings
IMAGE_DIRECTORY_ENTRY_IMPORT_MAPPINGS = {'VirtualAddress':'headers/optional_header/data_directory/import_table/virtual_address',
                                         'Size':'headers/optional_header/data_directory/import_table/size'}

# __IMAGE_DIRECTORY_ENTRY_RESOURCE_format__ -> CybOX Windows Executable File Object Data Directory Resource Table mappings
IMAGE_DIRECTORY_ENTRY_RESOURCE_MAPPINGS = {'VirtualAddress':'headers/optional_header/data_directory/resource_table/virtual_address',
                                           'Size':'headers/optional_header/data_directory/resource_table/size'}

# IMAGE_DIRECTORY_ENTRY_EXCEPTION -> CybOX Windows Executable File Object Data Directory Exception Table mappings 
IMAGE_DIRECTORY_ENTRY_EXCEPTION_MAPPINGS = {'VirtualAddress':'headers/optional_header/data_directory/exception_table/virtual_address',
                                            'Size':'headers/optional_header/data_directory/exception_table/size'}

# IMAGE_DIRECTORY_ENTRY_SECURITY -> CybOX Windows Executable File Object Data Directory Certificate Table mappings
IMAGE_DIRECTORY_ENTRY_SECURITY_MAPPINGS = {'VirtualAddress':'headers/optional_header/data_directory/certificate_table/virtual_address',
                                           'Size':'headers/optional_header/data_directory/certificate_table/size'}

# IMAGE_DIRECTORY_ENTRY_BASERELOC -> CybOX Windows Executable File Object Data Directory Base Relocation Table mappings
IMAGE_DIRECTORY_ENTRY_BASERELOC_MAPPINGS = {'VirtualAddress':'headers/optional_header/data_directory/base_relocation_table/virtual_address',
                                            'Size':'headers/optional_header/data_directory/base_relocation_table/size'}

# IMAGE_DIRECTORY_ENTRY_DEBUG -> CybOX Windows Executable File Object Data Directory Debug mappings
IMAGE_DIRECTORY_ENTRY_DEBUG_MAPPINGS = {'VirtualAddress':'headers/optional_header/data_directory/debug/virtual_address',
                                        'Size':'headers/optional_header/data_directory/debug/size'}

# IMAGE_DIRECTORY_ENTRY_COPYRIGHT -> CybOX Windows Executable File Object Data Directory Copyright mappings
IMAGE_DIRECTORY_ENTRY_COPYRIGHT_MAPPINGS = {'VirtualAddress':'No_Mapping',
                                            'Size':'No_Mapping'}

# IMAGE_DIRECTORY_ENTRY_ARCHITECTURE -> CybOX Windows Executable File Object Data Directory Architecture mappings
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE_MAPPINGS = {'VirtualAddress':'headers/optional_header/data_directory/architecture/virtual_address',
                                               'Size':'headers/optional_header/data_directory/architecture/size'}

# IMAGE_DIRECTORY_ENTRY_GLOBALPTR -> CybOX Windows Executable File Object Data Directory Global Pointer mappings
IMAGE_DIRECTORY_ENTRY_GLOBALPTR_MAPPINGS = {'VirtualAddress':'headers/optional_header/data_directory/global_ptr/virtual_address',
                                            'Size':'headers/optional_header/data_directory/global_ptr/size'}

# IMAGE_DIRECTORY_ENTRY_TLS -> CybOX Windows Executable File Object Data Directory Thread Local Storage Table mappings
IMAGE_DIRECTORY_ENTRY_TLS_MAPPINGS = {'VirtualAddress':'headers/optional_header/data_directory/tls_table/virtual_address',
                                      'Size':'headers/optional_header/data_directory/tls_table/size'}

# IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG -> CybOX Windows Executable File Object Data Directory Load Config Table mappings
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG_MAPPINGS = {'VirtualAddress':'headers/optional_header/data_directory/load_config_table/virtual_address',
                                              'Size':'headers/optional_header/data_directory/load_config_table/size'}

# __IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT_format__ -> CybOX Windows Executable File Object Data Directory Bound Imports mappings
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = {'VirtualAddress':'headers/optional_header/data_directory/bound_import/virtual_address',
                                      'Size':'headers/optional_header/data_directory/bound_import/size'}

# __IMAGE_DIRECTORY_ENTRY_IAT_format__ -> CybOX Windows Executable File Object Data Directory Import Address Table mappings
IMAGE_DIRECTORY_ENTRY_IAT_MAPPINGS = {'VirtualAddress':'headers/optional_header/data_directory/import_address_table/virtual_address',
                                      'Size':'headers/optional_header/data_directory/import_address_table/size'}

# IMAGE_DIRECTORY_DELAY_IMPORT -> CybOX Windows Executable File Object Data Directory Delay Import Descriptor mappings
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT_MAPPINGS = {'VirtualAddress':'headers/optional_header/data_directory/delay_import_descriptor/virtual_address',
                                               'Size':'headers/optional_header/data_directory/delay_import_descriptor/size'}

# IMAGE_DIRECTORY_COM_DESCRIPTOR -> CybOX Windows Executable File Object Data Directory CLR Runtime Header mappings
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR_MAPPINGS = {'VirtualAddress':'headers/optional_header/data_directory/clr_runtime_header/virtual_address',
                                                 'Size':'headers/optional_header/data_directory/clr_runtime_header/size'}

# IMAGE_DIRECTORY_RESERVED -> CybOX Windows Executable File Object Data Directory Reserved mappings
IMAGE_DIRECTORY_ENTRY_RESERVED_MAPPINGS = {'VirtualAddress':'headers/optional_header/data_directory/reserved/virtual_address',
                                           'Size':'headers/optional_header/data_directory/reserved/size'}

