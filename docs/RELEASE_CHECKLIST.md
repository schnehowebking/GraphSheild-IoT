# Release checklist

1. Review the staged diff and confirm no secrets, raw third-party datasets,
   manuscript files, local environments or obsolete confirmation archives are staged.
2. Confirm rights for redistributed derived evidence and the repository license.
3. Run `python scripts/build_manifest.py` after final source/document edits, then
   `python scripts/verify_manifest.py` and `python -m pytest tests -q`.
4. Run `python scripts/verify_portable_runtime.py` and
   `python scripts/verify_public_release.py --output results/release_check_NEW`.
5. Run `python scripts/smoke_public_bundle.py --output results/clean_check_NEW`.
   This creates a fresh manifested copy and generated outputs, reusing the installed
   interpreter/dependencies. It is not an actual OVS collection.
6. Commit/push the reviewed source, manifests and required evidence; confirm the
   Ubuntu GitHub Actions run succeeds. Local Windows replay cannot replace this.
7. Select a NEW release version, update citation metadata only to that actual
   release, regenerate the manifest, and test the final committed contents.
8. Publish the fixed tag/release and archive that exact revision. Confirm archived
   assets are complete and downloadable before citing the new version DOI.

Do not reuse the old release DOI for updated artifacts. No new release identifier,
publication date or DOI is assumed in this working tree. Do not regenerate or
edit scientific result files to make verification pass. Preserve previous data.
