"""Errors for the Nokia component."""
from homeassistant.exceptions import HomeAssistantError


class NokiaException(HomeAssistantError):
    """Base class for Nokia exceptions."""


class CannotLoginException(NokiaException):
    """Unable to login to the router."""