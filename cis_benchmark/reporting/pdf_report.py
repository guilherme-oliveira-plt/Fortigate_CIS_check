"""
PDF Report Generator
=====================
Generates PDF reports. Falls back to HTML if weasyprint is not installed.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class PDFReportGenerator:
    """Generate PDF compliance reports."""

    def __init__(self):
        self._weasyprint_available = False
        try:
            import weasyprint
            self._weasyprint_available = True
        except ImportError:
            logger.info("weasyprint not installed - PDF will fallback to HTML")

    @property
    def is_available(self) -> bool:
        return self._weasyprint_available

    def generate(self, html_content: str, output_path: str) -> bool:
        """
        Generate PDF from HTML content.
        Returns True if PDF was generated, False if fell back to HTML.
        """
        if self._weasyprint_available:
            try:
                import weasyprint
                html_doc = weasyprint.HTML(string=html_content)
                html_doc.write_pdf(output_path)
                logger.info(f"PDF report saved: {output_path}")
                return True
            except Exception as e:
                logger.error(f"PDF generation failed: {e}")

        # Fallback: save as HTML with .html extension
        fallback_path = str(output_path).replace('.pdf', '_report.html')
        Path(fallback_path).write_text(html_content, encoding="utf-8")
        logger.info(f"PDF unavailable, HTML report saved: {fallback_path}")
        return False
