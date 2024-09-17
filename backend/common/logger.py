import logging
import sys

# Create a logger
logger = logging.getLogger(__name__)

# Set the logging level
logger.setLevel(logging.INFO)

# Create a formatter
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# Create a stream handler (for console output)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(formatter)

# Create a file handler (for logging to a file)
file_handler = logging.FileHandler("app.log")
file_handler.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(stream_handler)
logger.addHandler(file_handler)

# Export the logger instance
error = logger.error
exception = logger.exception
info = logger.info
warning = logger.warning
debug = logger.debug
critical = logger.critical
