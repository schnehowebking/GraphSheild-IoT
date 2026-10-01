#!/usr/bin/env python3
"""One command for versioned reviewer-revision experiments (never overwrites)."""
import os
import sys
from pathlib import Path

for key in ["OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"]:
    os.environ.setdefault(key, "1")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if __name__ == "__main__":
    from reviewer_revision.pipeline import main
    main()
