import wardline.scanner as scanner
from wardline.scanner.analyzer import WardlineAnalyzer


def test_noop_analyzer_is_not_exported() -> None:
    assert scanner.__all__ == ["WardlineAnalyzer"]
    assert not hasattr(scanner, "NoOpAnalyzer")
    assert scanner.WardlineAnalyzer is WardlineAnalyzer
