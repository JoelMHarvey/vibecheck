"""Entry point for the composite action in action.yml.

Invoked by file path rather than as `python3 -m vibecheck.ghaction`, because
`-m` puts the working directory first on sys.path — and the working directory
is the repository being scanned, which may well have a `vibecheck` directory
of its own. Running a script by path puts *its* directory first instead, which
is exactly where the package lives.
"""

import sys

from vibecheck.ghaction import main

if __name__ == "__main__":
    sys.exit(main())
