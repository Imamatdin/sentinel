"""Prompt management with Jinja2 templates."""

from typing import Any, Optional
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from sentinel.logging_config import get_logger

logger = get_logger(__name__)


class PromptManager:
    """Manage prompt templates with Jinja2.

    Templates are loaded from a directory. Supports both file-based templates
    and inline string templates. Used by agents to render system prompts
    with context variables (target URL, recon data, findings, etc.).
    """

    def __init__(self, template_dir: Optional[Path] = None) -> None:
        if template_dir is None:
            template_dir = Path(__file__).parent.parent / "prompts"

        self.template_dir = template_dir
        self.template_dir.mkdir(parents=True, exist_ok=True)

        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )

        logger.debug("prompt_manager_initialized", template_dir=str(self.template_dir))

    def render(self, template_name: str, context: Optional[dict[str, Any]] = None) -> str:
        """Render a template file with context variables.

        Args:
            template_name: Filename in the template directory (e.g. "recon_system.j2")
            context: Variables to substitute into the template

        Returns:
            Rendered prompt string
        """
        try:
            template = self.env.get_template(template_name)
            return template.render(**(context or {}))
        except TemplateNotFound:
            logger.error("template_not_found", template_name=template_name)
            raise
        except Exception as e:
            logger.error("prompt_render_failed", template_name=template_name, error=str(e))
            raise

    def render_string(self, template_string: str, context: Optional[dict[str, Any]] = None) -> str:
        """Render a prompt from an inline string template."""
        try:
            template = self.env.from_string(template_string)
            return template.render(**(context or {}))
        except Exception as e:
            logger.error("string_template_render_failed", error=str(e))
            raise

    def add_template(self, name: str, content: str) -> None:
        """Create a new template file on disk."""
        path = self.template_dir / name
        path.write_text(content, encoding="utf-8")
        logger.debug("template_added", template_name=name)

    def list_templates(self) -> list[str]:
        """List all available template files."""
        return self.env.list_templates()
