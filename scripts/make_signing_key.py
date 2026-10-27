"""Make the server's badge-signing key.

    python3 scripts/make_signing_key.py

Prints a new secret for VIBECHECK_SIGNING_KEY (set it in Vercel's project
settings, Production only, marked sensitive) and the public key and key id
it will publish at /.well-known/vibecheck-key. Keep the secret nowhere else.

To rotate: make a new key, move the old public key (the "x" printed when it
was made, or read from /.well-known/vibecheck-key) into
VIBECHECK_OLD_PUBLIC_KEYS so reports signed with it still verify, then set
the new secret.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vibecheck.core.signing import Signer, b64url  # noqa: E402

if __name__ == "__main__":
    seed = os.urandom(32)
    signer = Signer(seed)
    print("VIBECHECK_SIGNING_KEY=" + b64url(seed))
    print("public key (x):  " + b64url(signer.public))
    print("key id (kid):    " + signer.kid)
