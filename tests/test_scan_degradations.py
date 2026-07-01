from __future__ import annotations

from phantom_secops.killchain import _scan_degradations, _render_scan_status


class TestScanDegradations:
    def test_empty_when_no_errors_and_not_mock(self):
        degradations = _scan_degradations(
            recon={}, vuln={}, mock=False,
        )
        assert degradations == []

    def test_mock_mode_always_empty(self):
        degradations = _scan_degradations(
            recon={"error": "nmap not found"}, vuln={"errors": ["nuclei not found"]},
            mock=True,
        )
        assert degradations == []

    def test_recon_error_appears_in_degradations(self):
        degradations = _scan_degradations(
            recon={"error": "nmap not found"}, vuln={}, mock=False,
        )
        assert "nmap" in degradations[0]
        assert len(degradations) == 1

    def test_vuln_errors_appear_in_degradations(self):
        degradations = _scan_degradations(
            recon={}, vuln={"errors": ["nuclei missing", "docker unavailable"]}, mock=False,
        )
        assert len(degradations) == 2
        assert all("nuclei" in e for e in degradations)

    def test_both_recon_and_vuln_errors_are_listed(self):
        degradations = _scan_degradations(
            recon={"error": "timeout"},
            vuln={"errors": ["nuclei crashed", "docker not found"]},
            mock=False,
        )
        assert len(degradations) == 3
        assert any("recon" in d for d in degradations)
        assert any("nuclei" in d for d in degradations)


class TestRenderScanStatus:
    def test_empty_degradations_returns_empty_string(self):
        assert _render_scan_status([]) == ""
        assert _render_scan_status(None) == ""

    def test_degraded_banner_includes_DEGRADED_and_INCOMPLETE(self):
        banner = _render_scan_status(["recon (nmap): timeout", "vuln-scan (nuclei): crash"])
        assert "DEGRADED" in banner
        assert "INCOMPLETE" in banner
        assert "timeout" in banner
        assert "crash" in banner
