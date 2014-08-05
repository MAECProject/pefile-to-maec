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
