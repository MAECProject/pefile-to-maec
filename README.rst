pefile-to-maec
==============

A Python library for converting output from Ero Carrera's `pefile <https://code.google.com/p/pefile/>`_ utility to MAEC XML content.  It is currently in the BETA phase.

pefile-to-maec uses the pefile package: "pefile is a multi-platform Python module to read and work with Portable Executable (aka PE) files. Most of the information in the PE Header is accessible, as well as all the sections, section's information and data."[1]

This package consists of a module that converts binary files into MAEC (``/pefile_to_maec``), and a script that uses that module (``pefile_to_maec.py``).

:Source: https://raw.githubusercontent.com/MAECProject/pefile-to-maec/master/pefile_to_maec.py
:MAEC: http://maec.mitre.org

Dependencies
------------

**python-maec** |maec version badge| |maec downloads badge|

**python-cybox** |cybox version badge| |cybox downloads badge|

**pefile** |pefile version badge| |pefile downloads badge|

.. |maec version badge| image:: https://pypip.in/v/maec/badge.png
   :target: https://pypi.python.org/pypi/maec/
.. |maec downloads badge| image:: https://pypip.in/d/maec/badge.png
   :target: https://pypi.python.org/pypi/maec/
.. |cybox version badge| image:: https://pypip.in/v/cybox/badge.png
   :target: https://pypi.python.org/pypi/cybox/
.. |cybox downloads badge| image:: https://pypip.in/d/cybox/badge.png
   :target: https://pypi.python.org/pypi/cybox/
.. |pefile version badge| image:: https://pypip.in/v/pefile/badge.png
   :target: https://pypi.python.org/pypi/pefile/
.. |pefile downloads badge| image:: https://pypip.in/d/pefile/badge.png
   :target: https://pypi.python.org/pypi/pefile/
   

Usage
-----

The script can be called with:

python pefile_to_maec.py input output [--deduplicate] [--dereference] [--normalize]

- ``input`` and ``output`` may be files or directories
- ``--deduplicate``, ``-dd``: deduplicate objects in MAEC output (Objects only)
- ``--dereference``, ``-dr``: dereference the MAEC output (Objects only)
- ``--normalize``, ``-n``: normalize the MAEC output (Objects only)

The module exposes the following functions:

-  ``generate_package_from_binary_filepath`` - given an filepath, return
   a python-maec Package object with the PEFile output.
   
To use these module functions, the module must first be installed with setuptools:

``python setup.py install``

Compatibility
-------------

The pefile-to-maec library is tested and written against python ``2.7.x``. Compatibility with other python versions is neither guaranteed nor implied.

Installation
------------

pefile-to-maec employs the `python-maec <https://pypi.python.org/pypi/maec/>`_ and `python-cybox <https://pypi.python.org/pypi/cybox/>`_ for the conversion to MAEC.

The pefile package does not require any external libraries if run from the 
command line.

If installing from source, ``setuptools`` is required.

The ``maec`` package depends on the following Python libraries: \* ``lxml`` >=
3.1.x \* ``python-cybox`` >= 2.1.x.x \* ``setuptools`` (only if installing
using setup.py)

For Windows installers of the above libraries, we recommend looking here:
http://www.lfd.uci.edu/~gohlke/pythonlibs. python-cybox can be found at
https://github.com/CybOXProject/python-cybox/releases.

To build ``lxml`` on Ubuntu, you will need the following packages from the
Ubuntu package repository:

-  python-dev
-  libxml2-dev
-  libxslt1-dev

For more information about installing lxml, see
http://lxml.de/installation.html

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
