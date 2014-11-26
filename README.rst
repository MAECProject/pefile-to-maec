pefile-to-maec
==============
v1.0.0-beta1

A Python library for converting output from Ero Carrera's `pefile <https://code.google.com/p/pefile/>`_ utility to MAEC XML content.  It is currently in the BETA phase.

pefile-to-maec uses the pefile package: "pefile is a multi-platform Python module to read and work with Portable Executable (aka PE) files. Most of the information in the PE Header is accessible, as well as all the sections, section's information and data."[1]

This package consists of a module that captures the pefile output for binary files in MAEC format (``/pefile_to_maec``), and a script that uses that module (``pefile_to_maec.py``).

:Source: https://github.com/MAECProject/pefile-to-maec
:MAEC: http://maec.mitre.org

Dependencies
------------
The pefile-to-maec script depends on the presence of certain packages/libraries
to function. Please refer to their installation documentation for installation
instructions.

-  `python-maec >=4.1.0.9 and <= 4.2.0.0 <https://pypi.python.org/pypi/maec>`_
-  `python-cybox >=2.1.0.8 and <= 2.2.0.0. <https://pypi.python.org/pypi/cybox>`_
-  `pefile >=1.2.10 <https://pypi.python.org/pypi/pefile>`_

Usage
-----

The script can be called with:

``python pefile_to_maec.py infile outfile``

Where ``infile`` refers to the input PE binary file and ``outfile`` the name of
the MAEC XML file to which the output will be written.

The module exposes the following functions:

-  ``generate_package_from_binary_filepath`` - given an filepath, return
   a python-maec Package object with the PEFile output.
   
To use these module functions, the module must first be installed with setuptools:

``python setup.py install``

At which point it can be used as a library:

``import pefile_to_maec``

Compatibility
-------------

The pefile-to-maec library is tested and written against python ``2.7.x``. Compatibility with other python versions is neither guaranteed nor implied.

Supported Features
------------------
The following features are mapped from the PEFile output and captured in MAEC:

- Metadata
    - File name (on disk)
    - File path
    - File size (in bytes)
    - Hashes (MD5, SHA1)
- DOS header
- File header
- Optional header
- Exports
- Imports
- Resource directories

Feedback
--------

Bug reports and feature requests are welcome and encouraged. Pull requests are
especially appreciated. Feel free to use the issue tracker on GitHub or send an
email directly to maec@mitre.org.
