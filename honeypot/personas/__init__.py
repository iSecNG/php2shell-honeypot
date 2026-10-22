"""Personas: the fake site served on top of the fake Apache/PHP stack."""

from ..config import Config
from .base import Persona, Request, Response
from .portal import PortalPersona
from .wordpress import WordPressPersona

PERSONAS: dict[str, type[Persona]] = {
    p.name: p for p in (WordPressPersona, PortalPersona)
}

__all__ = ["PERSONAS", "Persona", "Request", "Response", "load"]


def load(cfg: Config) -> Persona:
    """Instantiate the persona selected by HP_PERSONA."""
    try:
        return PERSONAS[cfg.persona](cfg)
    except KeyError:
        raise ValueError(
            f"unknown HP_PERSONA {cfg.persona!r}, "
            f"choose one of: {', '.join(PERSONAS)}"
        ) from None
