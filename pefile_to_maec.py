# -*- coding: Latin-1 -*-
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.

__version__ = '0.1.0a1'

import argparse
import sys
import os
try:
    import pefile
except ImportError:
    print 'Unable to import pefile'
    try:
        sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
        import pefile
    except Exception as err:
        print 'Unable to import pefile from parent directory.\n'
        print 'Please ensure that pefile resides in the current directory or \
                install pefile.\n'
        print 'ERROR MSG => %s' % err.message
        sys.exit(-1)
from pprint import pprint

from mappings.image_dos_header import IMAGE_DOS_HEADER_MAPPINGS
import maec.utils


class PefileParser(object):
    def __init__(self, pe):
        self.pe = pe
        self.pe_file_dictionary = {}
        self.process_pefile_object()

    def perform_mappings(self, struct_instance, object_mapping_dict):
        output_dict = {}
        for key, value in struct_instance.dump_dict().items():
            if key in object_mapping_dict:
                if isinstance(object_mapping_dict[key], str):
                    output_dict[object_mapping_dict[key]] = str(getattr(struct_instance, key))
                elif isinstance(object_mapping_dict[key], dict):
                    mapping_dict = object_mapping_dict[key]
                    # Handle any fields from which the value must be extracted
                    if 'Value' in mapping_dict:
                        child_value = mapping_dict['Value']
                        if child_value:
                            output_dict[mapping_dict['mapping']] = str(child_value.strip())
        return output_dict

    def parse_pe_headers(self):
        headers_dict = {}
        headers_dict['image_dos_header'] = self.perform_mappings(self.pe.DOS_HEADER, IMAGE_DOS_HEADER_MAPPINGS)
        return headers_dict

    def process_pefile_object(self):
        self.pe_file_dictionary = {'xsi:type':'WindowsExecutableFileObjectType'}
        self.pe_file_dictionary['headers'] = self.parse_pe_headers()
        pprint(self.pe_file_dictionary)

if __name__ == '__main__':

    # Setup the argument parser
    parser = argparse.ArgumentParser(description="Ero Carrera's Pefile module to MITRE MAEC Translator v" + __version__)
    parser.add_argument("input", help="the name of the input portable executable file to translate to MAEC")
    parser.add_argument("output", help="the name of the MAEC XML to which the output will be written")
    args = parser.parse_args()

    # Open the input file and instantiate pefile.PE
    try:
        pe = pefile.PE(args.input, fast_load=True)
    except pefile.PEFormatError as err:
        print err.message
        sys.exit(-1)
    # Instantiate the pefile parser and parse the pefile object
    parser = PefileParser(pe)
