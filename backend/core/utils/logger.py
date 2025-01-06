import logging
import sys

# Create a logger
logger = logging.getLogger("Audit Agent")

# Set the logging level to DEBUG
logger.setLevel(logging.DEBUG)

# Create a formatter
formatter = logging.Formatter("%(levelname)s: %(asctime)s - %(name)s - %(message)s")

# Create a stream handler (for console output)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(stream_handler)

# Export the logger instance
error = logger.error
exception = logger.exception
info = logger.info
warning = logger.warning
debug = logger.debug
critical = logger.critical
