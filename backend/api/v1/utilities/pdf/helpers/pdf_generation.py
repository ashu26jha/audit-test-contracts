import os
from pathlib import Path
from typing import Union

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright

from core.utils.logger import logger

from ..config import TEMPLATE_DIR


async def html_to_pdf(html_file: Union[str, Path], pdf_file: Union[str, Path]) -> None:
    """
    Convert HTML file to PDF using Playwright.

    Args:
        html_file: Path to the source HTML file
        pdf_file: Path where the PDF should be saved

    Raises:
        PlaywrightError: If there's an error during PDF generation
        FileNotFoundError: If the HTML file doesn't exist
    """
    if not os.path.exists(html_file):
        raise FileNotFoundError(f"HTML file not found: {html_file}")

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()

            # Set viewport width larger to accommodate code
            await page.set_viewport_size({"width": 1200, "height": 800})

            await page.goto(f"file://{html_file}")
            await page.wait_for_load_state("networkidle")

            # Ensure styles are loaded
            await page.wait_for_timeout(1000)

            pdf_options = {
                "path": pdf_file,
                "format": "A4",
                "print_background": True,
                "display_header_footer": False,
                "margin": {"top": "0mm", "right": "0mm", "bottom": "0mm", "left": "0mm"},
                "prefer_css_page_size": True,
            }

            await page.pdf(**pdf_options)
            await browser.close()
    except PlaywrightError as e:
        logger.error(f"Error during PDF generation: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during PDF generation: {str(e)}")
        raise


async def generate_pdf_from_html(html_content: str, pdf_filename: str) -> Path:
    """
    Convert HTML content to PDF and handle temporary file cleanup.

    Args:
        html_content: The HTML content to convert
        pdf_filename: Name for the generated PDF file

    Returns:
        Path to the generated PDF file

    Raises:
        IOError: If there's an error writing the temporary HTML file
        PlaywrightError: If there's an error during PDF generation

    Note:
        All files are created in and read from TEMPLATE_DIR for process safety.
    """
    # Ensure all paths are explicitly within TEMPLATE_DIR
    pdf_path = TEMPLATE_DIR / pdf_filename
    temp_html_path = TEMPLATE_DIR / f"temp_{pdf_filename}.html"

    try:
        # Write HTML to temporary file
        try:
            with open(temp_html_path, "w", encoding="utf-8") as file:
                file.write(html_content)
        except IOError as e:
            logger.error(f"Error writing temporary HTML file: {str(e)}")
            raise

        # Convert to PDF
        await html_to_pdf(temp_html_path, pdf_path)
        return pdf_path
    except Exception as e:
        logger.error(f"Error during PDF generation process: {str(e)}")
        raise
    finally:
        # Always cleanup temporary HTML file
        cleanup_temp_file(temp_html_path)


def cleanup_temp_file(file_path: Path) -> None:
    """
    Clean up a temporary file if it exists.

    Args:
        file_path: Path to the file to be cleaned up
    """
    try:
        if file_path.exists():
            os.remove(file_path)
    except Exception as e:
        logger.warning(f"Failed to cleanup temporary file {file_path}: {str(e)}")
