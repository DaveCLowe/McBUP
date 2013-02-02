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
import shutil
import logging
import hashlib

log = logging.getLogger()

def getMD5(filepath):
	"""Get MD5.
    @return: MD5.
    """
	return hashlib.md5(open(filepath, "rb").read()).hexdigest()

def moveAndHash(startPath, endPath):
	"""Move file and confirm hashes match.
	@param startPath: start path - inclusive of filename.
	@param endPath: destination directory - inclusive of filename.
	@return: bool indicating success.
	"""
	# Ensure there is a file to hash and move

	(startFileDir, startFileName) = os.path.split(os.path.abspath(startPath))
	destFileAndPath = os.path.join(endPath,startFileName)

	log.info("Copying file {} from {} to {} ".format(startFileName,startFileDir,destFileAndPath))

	firstHash = getMD5(startPath)
	
	if not os.path.isfile(destFileAndPath):
		# If the file does not already exist in the masters directory...
		log.info("Copying file to master directory")
		shutil.copy(os.path.abspath(startPath),destFileAndPath)
	else:
	    log.warning("File {} already exists in masters directory. Checking hash.".format(startFileName))

	if getMD5(destFileAndPath) == firstHash:
		log.info("Hash compare complete - match.")
		return True
	else:
		return False