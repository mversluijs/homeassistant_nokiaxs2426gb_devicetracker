"""Support for Nokia routers."""
from __future__ import annotations

import logging

from homeassistant.components.device_tracker import ScannerEntity, SourceType
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DEVICE_ICONS, DOMAIN, KEY_COORDINATOR, KEY_ROUTER
from .router import NokiaBaseEntity, NokiaRouter

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up device tracker for Nokia component."""
    router = hass.data[DOMAIN][entry.entry_id][KEY_ROUTER]
    coordinator = hass.data[DOMAIN][entry.entry_id][KEY_COORDINATOR]
    tracked = set()

    @callback
    def new_device_callback() -> None:
        """Add new devices if needed."""
        if not coordinator.data:
            return

        new_entities = []

        for mac, device in router.devices.items():
            if mac in tracked:
                continue

            new_entities.append(NokiaScannerEntity(coordinator, router, device))
            tracked.add(mac)

        async_add_entities(new_entities)

    entry.async_on_unload(coordinator.async_add_listener(new_device_callback))

    coordinator.data = True
    new_device_callback()


class NokiaScannerEntity(NokiaBaseEntity, ScannerEntity):
    """Representation of a device connected to a Nokia router."""

    def __init__(
        self, coordinator: DataUpdateCoordinator, router: NokiaRouter, device: dict
    ) -> None:
        """Initialize a Nokia device."""
        super().__init__(coordinator, router, device)
        self._hostname = self.get_hostname()
        # self._icon = DEVICE_ICONS.get(device["device_type"], "mdi:help-network")

    def get_hostname(self) -> str | None:
        """Return the hostname of the given device or None if we don't know."""
        if (hostname := self._device["name"]) == "--":
            return None

        return hostname

    @callback
    def async_update_device(self) -> None:
        """Update the Nokia device."""
        self._device = self._router.devices[self._mac]
        self._active = self._device["active"]

    @property
    def is_connected(self) -> bool:
        """Return true if the device is connected to the router."""
        return self._active

    @property
    def source_type(self) -> SourceType:
        """Return the source type."""
        return SourceType.ROUTER

    @property
    def ip_address(self) -> str:
        """Return the IP address."""
        return self._device["ip"]

    @property
    def mac_address(self) -> str:
        """Return the mac address."""
        return self._mac

    @property
    def hostname(self) -> str | None:
        """Return the hostname."""
        return self._hostname

    @property
    def icon(self) -> str:
        """Return device icon."""
        if self.is_connected:
            return "mdi:lan-connect"
        return "mdi:lan-disconnect"