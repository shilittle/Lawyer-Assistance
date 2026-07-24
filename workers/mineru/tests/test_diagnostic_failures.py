import unittest

from lawyer_assistance_mineru_worker.main import _reason
from lawyer_assistance_mineru_worker.runtime import RuntimeFailure


class DiagnosticFailureTests(unittest.TestCase):
    def test_diagnostic_engine_class_is_stable_but_production_failure_is_generic(self) -> None:
        self.assertEqual(
            _reason(RuntimeFailure("mineru_execution_failed_importerror_shapely_lib")),
            "mineru_execution_failed_importerror_shapely_lib",
        )
        self.assertEqual(_reason(RuntimeFailure("mineru_execution_failed")), "worker_failure")

    def test_unbounded_or_non_ascii_diagnostic_detail_is_not_returned(self) -> None:
        self.assertEqual(
            _reason(RuntimeFailure("mineru_execution_failed_" + "a" * 100)),
            "worker_failure",
        )
        self.assertEqual(
            _reason(RuntimeFailure("mineru_execution_failed_案件")),
            "worker_failure",
        )


if __name__ == "__main__":
    unittest.main()
