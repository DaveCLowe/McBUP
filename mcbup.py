#!/usr/bin/env python
#
# McBUP is a simple script to normalise McAfee Quarantine files (*.bup); hash, and search VirusTotals
# Public API for some more descriptive threat names. It has been developed because McAfee are too lazy
# to create their own threat names now that GTI/Artemis has come into play....
#
# Copyright (C) Dave Lowe 2012 <dave@davelowe.com.au>
#
# This file is part of McBUP.
# McBUP is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# McBUP is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with McBUP.  If not, see <http://www.gnu.org/licenses/>.
#

import sys
import os
import logging
import ConfigParser

from optparse import OptionParser
from lib.mcbup.common.constants import MCBUP_VERSION
from lib.mcbup.common.constants import MCBUP_LOGDIR
from lib.mcbup.common.constants import MCBUP_ROOT
from lib.mcbup.common.constants import MCBUP_MASTER_STORE
from lib.mcbup.common.constants import MCBUP_WORKING_STORE
from lib.mcbup.common.checkDependancies import checkDepends
from lib.mcbup.common.utils import moveAndHash
from lib.mcbup.fileParser import FileParser

__appname__ = 'mcbup'
__version__ = MCBUP_VERSION
__author__ = "Dave Lowe <dave@davelowe.com.au>"
__licence__ = "GPL"

log = logging.getLogger()

def main(argv=None):
    """Parse and check options"""

    if argv is None:
        argv = sys.argv[1:]

	usage = "usage: %prog -f BUPFILE -o OUTPUT"
	parser = OptionParser(usage=usage, version=__version__)
	
    parser.add_option("-c", action="store", type="string", dest="config", default = "", help="load configuration file")
    parser.add_option("-f", "--file", dest="filename", help="path to BUP FILENAME")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose")
    parser.add_option("-d", "--debug", action="store_true", dest="debug")
    parser.add_option("-q", "--quiet", action="store_true", dest="quiet")
    
    (options, args) = parser.parse_args(argv)

    if not (options.filename):
    	parser.error("incorrect number of options. \nYou must specify the FILENAME with the -f option.")
        sys.exit(2)

    if options.verbose:
        log.info("reading ... {0:s} ".format(options.filename))

    if options.config != "":
        fileConfig = options.config
    else:
        fileConfig = os.path.join(MCBUP_ROOT,"conf","mcbup.conf")

    Config = ConfigParser.ConfigParser()
    if os.access(fileConfig,os.R_OK):
        Config.read(fileConfig)
    else:
        print "Unable to load configuration file:", fileConfig
        sys.exit(1)

    keepMalware = Config.get('MALWARE','keepmasters')

    if Config.getboolean('MALWARE', 'convertnative'):
        print ("We will xor your file back to the native format. \nThis may trigger AV alerts, so make sure {0:s} is excluded from AV.".format(MCBUP_MASTER_STORE))
        print ("This is probably a bad idea, unless you want to submit binary to sandbox.")

    if options.quiet:   
        log.setLevel(logging.WARN)
    elif options.debug:
        log.setLevel(logging.DEBUG)
    
    # OK, so lets check everything is good to go
    checkDepends(options)

    # Sweet, let's roll
    thisIsBUP = FileParser(os.path.abspath(options.filename))

    # Take a copy of the bup file and ensure integrity
    moveAndHash(thisIsBUP.fileBUP,MCBUP_MASTER_STORE)

    # Create a working copy
    (fileDirectory, fileNameOnly) = os.path.split(thisIsBUP.fileBUP)

    moveAndHash(os.path.join(MCBUP_MASTER_STORE,fileNameOnly),MCBUP_WORKING_STORE)

if __name__ == "__main__":
    sys.exit(main())