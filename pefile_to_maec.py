# -*- coding: Latin-1 -*-
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# For more information, please refer to the LICENSE.txt file.

__version__ = '0.1.0b2'

import argparse
import os
from pprint import pprint
from pefile_to_maec import generate_package_from_binary_filepath
from maec.misc.options import ScriptOptions

def create_maec(inputfile, outpath, options):
    package = generate_package_from_binary_filepath(inputfile, options)
    package.to_xml_file(args.output)

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

    # Test if the input is a directory or file
    if os.path.isfile(args.input):
        outfilename = args.output
        # Test if the output is a directory
        # If so, concatenate "_maec.xml" to the input filename
        # and use this as the output filename
        if os.path.isdir(args.output):
            outfilename = os.path.join(args.output, str(os.path.basename(args.input))[:-4] + "_maec.xml")
        # If we're dealing with a single file, just call create_maec()
        create_maec(args.input, outfilename, options)
    # If a directory was specified, perform the corresponding conversion
    elif os.path.isdir(args.input):
        # Iterate and try to parse/convert each file in the directory
        for filename in os.listdir(args.input):
            # Only handle XML files
            if str(filename)[-3:] != "xml":
                print str("Error: {0} does not appear to be an XML file. Skipping.\n").format(filename)
                continue
            outfilename = str(filename)[:-4] + "_maec.xml"
            create_maec(os.path.join(args.input, filename), os.path.join(args.output, outfilename), options)
    else:
        print "Input file " + args.input + " does not exist"
