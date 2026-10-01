"""Canonical timestamped training entrypoint; historical source preserved in reviewer_revision/original_sources."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from reviewer_revision.train import main

if __name__ == "__main__":
    main()
