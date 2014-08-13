# -*- coding: Latin-1 -*-
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.

__version__ = '0.1.0a1'

import argparse
import sys
import os
from copy import deepcopy
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
import maec.utils
from maec.bundle.bundle import Bundle
from maec.bundle.behavior import Behavior
from maec.bundle.malware_action import MalwareAction
from maec.bundle.capability import Capability
from maec.bundle.bundle_reference import BundleReference
from maec.package.analysis import Analysis
from maec.package.malware_subject import MalwareSubject, MalwareSubjectRelationshipList
from maec.package.package import Package
from cybox.utils import Namespace
from cybox.core import AssociatedObjects, AssociatedObject, Object, AssociationType, RelatedObject
from cybox.common.tools import ToolInformation


class PefileToMAEC(object):
    def __init__(self, pefile_parser):
        self.pefile_parser = pefile_parser
        NS = Namespace("http://code.google.com/p/pefile/", "EroCarrera")
        maec.utils.set_id_namespace(NS)
        self.package = Package()
        self.generate_maec()

    def create_object_dict(self, properties_dict):
        object_dict = {'id': maec.utils.idgen.create_id(prefix="object"), 'properties': properties_dict}
        return object_dict

    def populate(self, entry_dict, static_bundle, malware_subject=None):
        object_dict = self.create_object_dict(entry_dict)
        static_bundle.add_object(Object.from_dict(object_dict))

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
        entry_dict = self.pefile_parser.pefile_dict
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
    def __init__(self, pe):
        self.pe = pe
        self.pefile_dict = {}
        self.handle_pefile_object()

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

    def perform_mapping(self, struct_dict, object_mapping_dict):
        output_dict = {}
        for key, value in struct_dict.items():
            if key in object_mapping_dict:
                if isinstance(object_mapping_dict[key], str):
                    self.set_dictionary_value(output_dict, object_mapping_dict[key], struct_dict[key])
            if isinstance(value, dict):
                mapping_dict = object_mapping_dict[key]
                for k,v in value.items():
                    if k == 'Value':
                        child_value = v
                        self.set_dictionary_value(output_dict, mapping_dict, str(child_value).strip())

        return output_dict

    def process_headers(self):
        headers_dict = {}

        struct_dos_dict = self.pe.DOS_HEADER.dump_dict
        struct_file_dict = self.pe.FILE_HEADER.dump_dict
        struct_optional32_dict = self.pe.OPTIONAL_HEADER.dump_dict

        headers_dict['dos_header'] = self.perform_mapping(struct_dos_dict(), IMAGE_DOS_HEADER_MAPPINGS)
        headers_dict['file_header'] = self.perform_mapping(struct_file_dict(), IMAGE_FILE_HEADER_MAPPINGS)
        headers_dict['optional_header'] = self.perform_mapping(struct_optional32_dict(), IMAGE_OPTIONAL_HEADER32_MAPPINGS)
        return headers_dict

    def handle_pefile_object(self):
        self.pefile_dict = {'xsi:type':'WindowsExecutableFileObjectType'}
        self.pefile_dict['headers'] = {}
        self.pefile_dict['headers'] = self.process_headers()


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
    # Instantiate the MAEC translator and perform the translation
    maec_translator = PefileToMAEC(parser)
    # Output the MAEC Package (generated from pefile output) as XML
    maec_translator.package.to_xml_file(args.output, {"http://code.google.com/p/pefile/":"EroCarrera"})

