"""plsk2sa - migrate Plesk hostings to a standalone Ubuntu stack."""

import logging

__version__ = "0.1.0"

# Library convention: stay silent unless the application (CLI/GUI) configures logging.
logging.getLogger("plsk2sa").addHandler(logging.NullHandler())
