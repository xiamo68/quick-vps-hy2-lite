from io import BytesIO
from pathlib import Path
import tarfile
from tempfile import TemporaryDirectory
import unittest

from deploy.operate_install import unpack


class OperateInstallTests(unittest.TestCase):
    def test_rejects_archive_files_outside_backup_manifest(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "backup.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                item = tarfile.TarInfo("../outside")
                item.size = 1
                archive.addfile(item, BytesIO(b"x"))
            stage = root / "stage"
            stage.mkdir()
            with self.assertRaises(ValueError):
                unpack(path, stage)
            self.assertFalse((root / "outside").exists())
