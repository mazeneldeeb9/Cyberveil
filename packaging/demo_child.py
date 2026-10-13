"""Harmless, bounded helper. Never loads the app or accepts executable commands."""

import os
import time

os.write(1, b"ready\n")
time.sleep(120)
