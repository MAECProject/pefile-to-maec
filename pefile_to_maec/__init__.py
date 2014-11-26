import pefile_to_maec
import pefile_parser

__version__ = '1.0.0-beta1'

def generate_package_from_binary_filepath(input_path, options = None):
    "Accept a filepath to a PE file and return a MAEC Package object"
    # Instantiate the pefile parser and parse the pefile object
    parser = pefile_parser.PefileParser(input_path)
    # Instantiate the MAEC translator and perform the translation
    maec_translator = pefile_parser.PefileToMAEC(parser)
    
    package = maec_translator.package
    
    package.__input_namespaces__["http://code.google.com/p/pefile/"] = "pefile"
    
    for malware_subject in package.malware_subjects:
        if options:
            if options.normalize_bundles:
                malware_subject.normalize_bundles()
            if options.deduplicate_bundles:
                malware_subject.deduplicate_bundles()
            if options.dereference_bundles:
                malware_subject.dereference_bundles()
    
    # return the MAEC Package object
    return package
