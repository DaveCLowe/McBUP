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

import os
import sys
import time
import shutil
import logging

from lib.mcbup.common.constants import MCBUP_ROOT
from lib.mcbup.common.constants import MCBUP_MASTER_STORE
from lib.mcbup.common.utils import moveAndHash

log = logging.getLogger()

def xorMeBaby(filepath):
    b = bytearray(open(filepath, 'rb').read())
    for i in range(len(b)):
        b[i] ^= 0x6A

    # Save file back
    open(filepath, 'wb').write(b)

class FileParser(object):
	"""docstring for FileParser"""
	def __init__(self, fileBUP):
		super(FileParser, self).__init__()
		self.fileBUP = fileBUP
		

	def processBUP(self, fileBUP):
		print ("Processing {!s}").format(fileBUP)
		# Extract the bup file

		# Test for a valid File_*

		# Generate MD5

		# 

		sys.exit(0)
		# Remove the directory from the variable
		fileBUP = os.path.split(fileBUP)[1]

		# Lets store the original BUP file under masters

		dirname = os.path.join(samplesHome,hostname,fileBUP + ".dir")
		if not os.path.exists(dirname):
		    if VERBOSE: print "Making working location for bup archive: %s" % fileBUP
		    os.makedirs(dirname)
		else:
		    log.error("BUP file working archive directory already exists for %s! Failing" % fileBUP)
		    return 1

		os.system("7z e " + os.path.join("/tmp/",fileBUP) + " -o" + dirname + " > /dev/null")

		dirList = os.listdir(dirname)
		for fname in dirList:
		    if fname == "Details":
		        xorMeBaby(os.path.join(dirname,fname))
		    elif "File_" in fname:
		        xorMeBaby(os.path.join(dirname,fname))

		return 0