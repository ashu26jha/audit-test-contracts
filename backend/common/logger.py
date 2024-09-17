from __future__ import annotations

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Expose logging methods
debug = logger.debug
info = logger.info
warning = logger.warning
error = logger.error
critical = logger.critical
exception = logger.exception
