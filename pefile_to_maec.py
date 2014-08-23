# -*- coding: Latin-1 -*-
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.

__version__ = '0.1.0a3'

import argparse
import sys
import os
from copy import deepcopy
import hashlib
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
from mappings.image_file_header import IMAGE_FILE_HEADER_MAPPINGS
from mappings.image_optional_header import IMAGE_OPTIONAL_HEADER32_MAPPINGS
from mappings.image_sections import IMAGE_SECTION_HEADER_MAPPINGS
from mappings.image_imports import IMAGE_IMPORT_MAPPINGS
import maec.utils
from maec.utils import Namespace
from maec.bundle.bundle import Bundle
from maec.bundle.behavior import Behavior
from maec.bundle.malware_action import MalwareAction
from maec.bundle.capability import Capability
from maec.bundle.bundle_reference import BundleReference
from maec.package.analysis import Analysis
from maec.package.malware_subject import MalwareSubject, MalwareSubjectRelationshipList
from maec.package.package import Package
from cybox.core import AssociatedObjects, AssociatedObject, Object, AssociationType, RelatedObject
from cybox.common.tools import ToolInformation
from cybox.objects.file_object import File
from cybox.common import Hash, HashList


class PefileToMAEC(object):
    def __init__(self, pefile_parser):
        self.pefile_parser = pefile_parser
        NS = Namespace("http://code.google.com/p/pefile/", "pefile")
        maec.utils.set_id_namespace(NS)
        self.package = Package()
        self.generate_maec()

    def create_object_dict(self, properties_dict):
        object_dict = {'id': maec.utils.idgen.create_id(prefix="object"), 'properties': properties_dict}
        return object_dict

    def populate(self, entry_dict, static_bundle, malware_subject=None):
        if 'file' in entry_dict and len(entry_dict['file'].keys()) > 1:
            file_dict = self.create_object_dict(entry_dict['file'])
            if malware_subject:
                malware_subject.malware_instance_object_attributes = Object.from_dict(file_dict)
            else:
                static_bundle.add_object(Object.from_dict(file_dict))
        if 'pe' in entry_dict and len(entry_dict['pe'].keys()) > 1:
            pe_dict = self.create_object_dict(entry_dict['pe'])
            static_bundle.add_object(Object.from_dict(pe_dict))

    def generate_analysis(self, static_bundle):
        analysis = Analysis()
        analysis.type = 'triage'
        analysis.method = 'static'
        analysis.add_tool(ToolInformation.from_dict({'id': maec.utils.idgen.create_id(prefix="tool"),
                'vendor': 'Ero Carrera',
                'name': 'pefile'}))
        findings_bundle_reference = []
        if self.bundle_has_content(static_bundle):
            findings_bundle_reference.append(BundleReference.from_dict({'bundle_idref':static_bundle.id}))
        analysis.findings_bundle_reference = findings_bundle_reference
        return analysis

    def bundle_has_content(self, bundle):
        if bundle.actions and len(bundle.actions) > 0:
            return True
        if bundle.objects and len(bundle.objects) > 0:
            return True
        if bundle.behaviors and len(bundle.behaviors) > 0:
            return True
        return False

    def generate_malware_subjects(self):
        entry_dict = self.pefile_parser.entry_dict
        malware_subject = MalwareSubject()
        entry_dict['id'] = malware_subject
        static_bundle = Bundle(None, False, '4.1', 'static analysis tool output')
        self.populate(entry_dict, static_bundle, malware_subject)
        malware_subject.add_analysis(self.generate_analysis(static_bundle))
        if self.bundle_has_content(static_bundle):
            malware_subject.add_findings_bundle(static_bundle)
        self.package.add_malware_subject(malware_subject)
        
    def generate_maec(self):
        self.generate_malware_subjects()

class PefileParser(object):
    def __init__(self, infile):
        self.infile = infile
        self.root_entry = None
        self.entry_dict = {}
        self.process_entry()

    # Build a nested dictionary from a list
    # Set it to a value
    def build_nested_dictionary(self, child_list, value):
        nested_dict = {}
        if len(child_list) == 1:
            nested_dict[child_list[0]] = value
            return nested_dict

        for list_item in child_list:
            next_index = child_list.index(list_item) + 1
            nested_dict[list_item] = self.build_nested_dictionary(child_list[next_index:], value)
            break

        return nested_dict

    # Function for merging multiple dictionaries
    def dict_merge(self, target, *args):
      # Merge multiple dicts
      if len(args) > 1:
        for obj in args:
         self.dict_merge(target, obj)
        return target

      # Recursively merge dicts and set non-dict values
      obj = args[0]
      if not isinstance(obj, dict):
        return obj
      for k, v in obj.iteritems():
        if k in target and isinstance(target[k], dict):
          self.dict_merge(target[k], v)
        else:
          target[k] = deepcopy(v)
      return target

    def set_dictionary_value(self, dictionary, key, value):
        if '/' in key:
            split_names = key.split('/')
            if split_names[0] not in dictionary:
                dictionary[split_names[0]] = self.build_nested_dictionary(split_names[1:], value)
            else:
                self.dict_merge(dictionary[split_names[0]], self.build_nested_dictionary(split_names[1:], value))
        else:
            dictionary[key] = value

    def perform_mapping(self, struct_dict, element_mapping_dict):
        output_dict = {}
        for key, value in struct_dict.items():
            if key in element_mapping_dict:
                if isinstance(value, str):
                    self.set_dictionary_value(output_dict, element_mapping_dict[key], value)
                elif isinstance(value, dict):
                    for k,v in value.items():
                        if k == 'Value':
                            self.set_dictionary_value(output_dict,
                                    element_mapping_dict[key], value[k])
                elif isinstance(value, list):
                    for entry in value:
                        for k,v in entry.items():
                            if k == 'Value':
                                self.set_dictionary_value(output_dict,
                                        element_mapping_dict[key], entry[k])

        return output_dict

    def perform_mappings(self, element_list, element_mapping_dict):
        output_dict = {}
        for element in element_list:
            print element
    def handle_input_file(self):
        try:
            self.root_entry = pefile.PE(self.infile, fast_load=True)
        except pefile.PEFormatError:
            return None

    def handle_file_object(self):
        file_dictionary = {}
        file_dictionary['xsi:type'] = 'FileObjectType'
        file_dictionary['file_name'] = os.path.basename(self.infile)
        file_dictionary['file_path'] = os.path.abspath(self.infile)
        file_dictionary['size_in_bytes'] = os.path.getsize(self.infile)

        return file_dictionary

    def parse_headers(self):
        headers_dictionary = {}
        headers_dictionary['dos_header'] = self.perform_mapping(
                self.root_entry.DOS_HEADER.dump_dict(),
                IMAGE_DOS_HEADER_MAPPINGS)
        headers_dictionary['file_header'] = self.perform_mapping(
                self.root_entry.FILE_HEADER.dump_dict(),
                IMAGE_FILE_HEADER_MAPPINGS)
        headers_dictionary['optional_header'] = self.perform_mapping(
                self.root_entry.OPTIONAL_HEADER.dump_dict(),
                IMAGE_OPTIONAL_HEADER32_MAPPINGS)

        return headers_dictionary

    def get_hash_list(self, item):
        hash_list = []
        hash_methods = [
                item.get_hash_md5(),
                item.get_hash_sha1(),
                item.get_hash_sha256(),
                item.get_hash_sha512()]
        for hash_method in hash_methods:
            hash_list.append(hash_method)

        return hash_list

    def get_entropy(self, item):
        entropy_dict = {}
        entropy_dict['value'] = item.get_entropy()

        return entropy_dict

    def parse_sections(self):
        sections_list = []
        for section in self.root_entry.sections:
            section_dict = {}
            section_dict = self.perform_mapping(section.dump_dict(),
                    IMAGE_SECTION_HEADER_MAPPINGS)
            section_dict['data_hashes'] = self.get_hash_list(section)
            section_dict['entropy'] = self.get_entropy(section)
            sections_list.append(section_dict)

        return sections_list

    def load_data_directories(self):
        self.root_entry.parse_data_directories( directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT'] ] )

    def parse_import_directory(self):
        imports_list = []

        for entry in self.root_entry.DIRECTORY_ENTRY_IMPORT:
            library_dictionary = {}
            api_list = []
            library_dictionary['file_name'] = entry.dll
            library_dictionary['imported_functions'] = api_list
            for imp in entry.imports:
                api_list.append({'function_name': imp.name})
            imports_list.append(library_dictionary)

        return imports_list

    def handle_pe_object(self):
        pe_dictionary = {'xsi:type': 'WindowsExecutableFileObjectType'}
        pe_dictionary['headers'] = self.parse_headers()
        pe_dictionary['sections'] = self.parse_sections()
        
        self.load_data_directories()
        pe_dictionary['imports'] = self.parse_import_directory()

        return pe_dictionary

    def process_entry(self):
        self.handle_input_file()

        if self.root_entry:
            self.entry_dict['file'] = self.handle_file_object()
            self.entry_dict['pe'] = self.handle_pe_object()
        else:
            print 'Error: Not a valid PE file.'
            sys.exit(-1)

if __name__ == '__main__':

    # Setup the argument parser
    parser = argparse.ArgumentParser(description="Ero Carrera's Pefile module to MITRE MAEC Translator v" + __version__)
    parser.add_argument("input", help="the name of the input portable executable file to translate to MAEC")
    parser.add_argument("output", help="the name of the MAEC XML to which the output will be written")
    args = parser.parse_args()

    # Instantiate the pefile parser and parse the pefile object
    parser = PefileParser(args.input)
    # Instantiate the MAEC translator and perform the translation
    maec_translator = PefileToMAEC(parser)
    # Output the MAEC Package (generated from pefile output) as XML
    maec_translator.package.to_xml_file(args.output, {"http://code.google.com/p/pefile/":"pefile"})

