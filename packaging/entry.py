"""Entry point of the packaged program.

Started without arguments (e.g. by double-click) it opens the graphical
wizard; with arguments it behaves like the `plsk2sa` command line tool.
"""

import sys

from plsk2sa.cli import main

if __name__ == "__main__":
    argv = sys.argv[1:] or ["ui"]
    sys.exit(main(argv))
