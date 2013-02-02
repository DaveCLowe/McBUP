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

MCBUP_ROOT = os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "..", ".."))
MCBUP_LOGDIR = os.path.join(MCBUP_ROOT,'log')
MCBUP_VERSION = "0.1"
MCBUP_MASTER_STORE = os.path.join(MCBUP_ROOT,'masters')
MCBUP_WORKING_STORE = os.path.join(MCBUP_ROOT,'working')