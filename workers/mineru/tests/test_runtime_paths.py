import os
import unittest
from pathlib import Path

from lawyer_assistance_mineru_worker.runtime import path_within_directory


class RuntimePathTests(unittest.TestCase):
    def test_model_path_is_bounded_to_exact_root(self) -> None:
        root = Path(r"C:\component\models")
        self.assertTrue(path_within_directory(root / "pipeline", root))
        self.assertFalse(path_within_directory(Path(r"C:\component\models-escape"), root))
        self.assertFalse(path_within_directory(Path(r"D:\component\models\pipeline"), root))

    @unittest.skipUnless(os.name == "nt", "Windows extended-length path spelling")
    def test_extended_length_and_normal_windows_paths_have_same_identity(self) -> None:
        root = Path(r"C:\component\models")
        extended = Path(r"\\?\C:\component\models\pipeline")
        self.assertTrue(path_within_directory(extended, root))
        self.assertTrue(path_within_directory(root / "pipeline", Path(r"\\?\C:\component\models")))


if __name__ == "__main__":
    unittest.main()
