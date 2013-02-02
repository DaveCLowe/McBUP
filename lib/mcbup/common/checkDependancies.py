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
import logging
import sys
import fnmatch

from lib.mcbup.common.constants import MCBUP_LOGDIR
from lib.mcbup.common.constants import MCBUP_MASTER_STORE
from lib.mcbup.common.constants import MCBUP_WORKING_STORE

log = logging.getLogger()

class checkDepends():  
    def checkDirs(self):
        """Checks if required directory structure exists, and if not - creates."""
        for folder in [MCBUP_LOGDIR,MCBUP_MASTER_STORE,MCBUP_WORKING_STORE]:
            if not os.path.exists(folder):
                try:
                    os.makedirs(folder)
                except OSError as e:
                    print("Unable to create logging directory {0:s} ".format(folder))
                    sys.exit(1)


    def checkPythonVersion(self):
        """Checks if Python version is supported.
        """
        version = sys.version.split()[0]
        if version < "2.6" or version >= "3":
            print("You are running an incompatible version of Python, please use 2.6 or 2.7")
            sys.exit(1)

    def init_logging(self):
        """Initialize logging."""
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s ',  datefmt='%Y/%m/%d %I:%M:%S %p')
        sh = logging.StreamHandler()
        sh.setFormatter(formatter)
        log.addHandler(sh)
        fh = logging.FileHandler(os.path.join(MCBUP_LOGDIR, "mcbup.log"))
        fh.setFormatter(formatter)
        log.addHandler(fh)
        log.setLevel(logging.INFO)
    

    def checkInputs(self,options):
        if not os.path.isfile(options.filename):
            log.error("You crazy man! Thats not a file!")
            sys.exit(2)

        if not fnmatch.fnmatch(options.filename, '*.bup'):
            log.error("Sorry mate, I only eat bup files.")
            sys.exit(1)

    def __init__(self,options):
        self.checkDirs()
        self.checkPythonVersion()
        self.init_logging()
        self.checkInputs(options)