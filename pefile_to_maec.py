# -*- coding: Latin-1 -*-
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# For more information, please refer to the LICENSE.txt file.

__version__ = '0.1.0b2'

import argparse
from pprint import pprint
from pefile_to_maec import generate_package_from_binary_filepath
from maec.misc.options import ScriptOptions

if __name__ == '__main__':

    # Setup the argument parser
    parser = argparse.ArgumentParser(description="Ero Carrera's Pefile module to MITRE MAEC Translator v" + __version__)
    parser.add_argument("input", help="the name of the input portable executable file to translate to MAEC")
    parser.add_argument("output", help="the name of the MAEC XML to which the output will be written")
    parser.add_argument("--deduplicate", "-dd", help="deduplicate the MAEC output (Objects only)", action="store_true", default=False)
    parser.add_argument("--normalize", "-n", help="normalize the MAEC output (Objects only)", action="store_true", default=False)
    parser.add_argument("--dereference", "-dr", help="dereference the MAEC output (Objects only)", action="store_true", default=False)
    args = parser.parse_args()

    # Build up the options instance based on the command-line input
    options = ScriptOptions()
    options.deduplicate_bundles = args.deduplicate
    options.normalize_bundles = args.normalize
    options.dereference_bundles = args.dereference

    package = generate_package_from_binary_filepath(args.input, options)
    package.to_xml_file(args.output)
