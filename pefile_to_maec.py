# -*- coding: Latin-1 -*-
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.

__version__ = 0.1
import argparse
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import pefile

from mappings.image_dos_header import IMAGE_DOS_HEADER_MAPPINGS
from mappings.image_file_header import IMAGE_FILE_HEADER_MAPPINGS
from mappings.image_nt_headers import IMAGE_NT_HEADERS_MAPPINGS
from mappings.image_optional_header import IMAGE_OPTIONAL_HEADER32_MAPPINGS

class pefile_parser(object):
    '''Parses a pefile.PE object.

        Methods:
            process_pefile:     TODO

    '''
    def __init__(self, pe):
        self.pe = pe
        self.headers = {}
        self.process_pefile()

    def set_dictionary_value(self, dictionary, key, value):
        dictionary[key] = value

    def perform_mappings(self, struct_inst, object_mapping_dict):
        output_dict = {}
        for key, value in struct_inst.dump_dict().items():
            if key in object_mapping_dict:
                if isinstance(object_mapping_dict[key], str):
                    self.set_dictionary_value(output_dict, object_mapping_dict[key], str(getattr(struct_inst, key)))
                elif isinstance(object_mapping_dict[key], dict):
                    mapping_dict = object_mapping_dict[key]
                    # Handle any fields from which the value must be extracted
                    if 'Value' in mapping_dict:
                        child_value = mapping_dict['Value']
                        if child_value:
                            self.set_dictionary_value(output_dict, mapping_dict['mapping'], str(child_value.strip()))

        return output_dict

    def process_headers(self):
        pe_file_dictionary = {'xsi:type':'WindowsExecutableFileObjectType'}
        pe_file_dictionary['headers'] = {}

        pe_file_dictionary['headers']['image_dos_header'] = self.perform_mappings(self.pe.DOS_HEADER, IMAGE_DOS_HEADER_MAPPINGS)
        pe_file_dictionary['headers']['image_file_header'] = self.perform_mappings(self.pe.FILE_HEADER, IMAGE_FILE_HEADER_MAPPINGS)
        pe_file_dictionary['headers']['image_nt_header'] = self.perform_mappings(self.pe.NT_HEADERS, IMAGE_NT_HEADERS_MAPPINGS)
        pe_file_dictionary['headers']['image_optional_header'] = self.perform_mappings(self.pe.OPTIONAL_HEADER, IMAGE_OPTIONAL_HEADER32_MAPPINGS)

        return pe_file_dictionary

    def process_pefile(self):
        from pprint import pprint
        pe_dict = self.process_headers()
        pprint(pe_dict)
        
if __name__ == '__main__':

    # Setup the argument parser
    parser = argparse.ArgumentParser(description="Ero Carerra's Pefile module to MAEC Translator v" + str(__version__))
    parser.add_argument("input", help="the name of the input portable executable file to translate to MAEC")
    parser.add_argument("output", help="the name of the MAEC XML to which the output will be written")
    args = parser.parse_args()

    # Open the input file and instantiate pefile.PE
    pe = pefile.PE(args.input, fast_load=True)
    # Instantiate the Pefile Parser and perform the parsing
    parser = pefile_parser(pe)

