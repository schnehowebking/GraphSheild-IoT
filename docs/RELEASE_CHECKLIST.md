# Public reviewer release checklist

1. Run `python scripts/build_reviewer_evidence_archive.py --source results/reviewer_revision_v1` after any complete controlled rerun.
2. Run `python scripts/build_manifest.py`.
3. Run `python scripts/verify_manifest.py`.
4. Run `python scripts/verify_release_archives.py`.
5. Run `python -m pytest tests -q` on Python 3.13.
6. Confirm `git status` contains only intended source, metadata and artifact changes.
7. Confirm no raw datasets, manuscript files, credentials, virtual environments or superseded pilot results are tracked.
8. Commit and push the exact reviewed state.
9. Enable the public repository in Zenodo before publishing the GitHub release.
10. GitHub release `v1.0.0` is archived by Zenodo as DOI `10.5281/zenodo.23084542`; record this release-specific DOI in the manuscript and response letter.

If the authors later replace the research-evaluation license with an open-source
license, make that change before tagging and describe it in the release notes.
