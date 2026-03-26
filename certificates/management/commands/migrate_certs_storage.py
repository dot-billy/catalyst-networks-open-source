import os
import shutil
from pathlib import Path
from typing import List, Tuple

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Move certificate files from MEDIA_ROOT to CERT_STORAGE_ROOT preserving relative structure."

    def add_arguments(self, parser):
        parser.add_argument(
            "--execute",
            action="store_true",
            help="Actually perform the move. Without this flag, a dry run is performed.",
        )
        parser.add_argument(
            "--subdirs",
            nargs="*",
            default=["ca", "certs"],
            help="Relative subdirectories to migrate under the storage root (default: ca certs).",
        )
        parser.add_argument(
            "--skip-existing",
            action="store_true",
            help="Skip files that already exist at the destination instead of overwriting.",
        )

    def handle(self, *args, **options):
        old_root = Path(settings.MEDIA_ROOT).resolve()
        new_root = Path(getattr(settings, "CERT_STORAGE_ROOT", settings.MEDIA_ROOT)).resolve()
        subdirs: List[str] = options["subdirs"]
        execute: bool = options["execute"]
        skip_existing: bool = options["skip_existing"]

        if old_root == new_root:
            self.stdout.write(self.style.WARNING("MEDIA_ROOT and CERT_STORAGE_ROOT are the same. Nothing to migrate."))
            return

        if not old_root.exists():
            self.stdout.write(self.style.WARNING(f"Old root does not exist: {old_root}"))
            return

        self.stdout.write(f"Old root: {old_root}")
        self.stdout.write(f"New root: {new_root}")
        self.stdout.write(f"Subdirs: {', '.join(subdirs)}")
        self.stdout.write(f"Mode: {'EXECUTE' if execute else 'DRY RUN'}")
        self.stdout.write(f"Skip existing: {skip_existing}")
        self.stdout.write("")

        planned_moves: List[Tuple[Path, Path]] = []
        for sub in subdirs:
            src_dir = old_root / sub
            if not src_dir.exists():
                self.stdout.write(self.style.WARNING(f"Skipping missing directory: {src_dir}"))
                continue

            for root, _, files in os.walk(src_dir):
                root_path = Path(root)
                for fname in files:
                    src_file = root_path / fname
                    # Compute the relative path from old_root to preserve structure (e.g., ca/1/file.key)
                    rel_path = src_file.relative_to(old_root)
                    dest_file = new_root / rel_path
                    planned_moves.append((src_file, dest_file))

        if not planned_moves:
            self.stdout.write(self.style.WARNING("No files found to migrate."))
            return

        self.stdout.write(f"Found {len(planned_moves)} files to migrate.")

        moved_count = 0
        skipped_count = 0
        for src, dest in planned_moves:
            if skip_existing and dest.exists():
                self.stdout.write(self.style.WARNING(f"SKIP (exists): {dest}"))
                skipped_count += 1
                continue

            self.stdout.write(f"{'MOVE' if execute else 'WOULD MOVE'}: {src} -> {dest}")
            if execute:
                dest.parent.mkdir(parents=True, exist_ok=True)
                # Use shutil.move which handles cross-device moves
                shutil.move(str(src), str(dest))
                moved_count += 1

        self.stdout.write("")
        if execute:
            self.stdout.write(self.style.SUCCESS(f"Moved {moved_count} files. Skipped {skipped_count} existing files."))
            # Optional: try to remove empty directories under old_root/subdirs
            self._cleanup_empty_dirs(old_root, subdirs)
        else:
            self.stdout.write(self.style.WARNING("Dry run complete. Re-run with --execute to perform the migration."))

    def _cleanup_empty_dirs(self, old_root: Path, subdirs: List[str]) -> None:
        """
        Remove empty directories under old_root/subdir trees to tidy up after migration.
        """
        for sub in subdirs:
            start = old_root / sub
            if not start.exists():
                continue
            # Walk bottom-up to remove deepest empty directories first
            for root, dirs, _ in os.walk(start, topdown=False):
                for d in dirs:
                    dir_path = Path(root) / d
                    try:
                        # Remove only if empty
                        if not any(dir_path.iterdir()):
                            dir_path.rmdir()
                            self.stdout.write(f"Removed empty dir: {dir_path}")
                    except Exception:
                        # Ignore errors silently; directories may not be empty due to concurrent writes
                        pass

