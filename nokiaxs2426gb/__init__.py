"""Support for Nokia routers."""
from __future__ import annotations

from datetime import timedelta
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import (
    DOMAIN,
    KEY_COORDINATOR,
    # KEY_COORDINATOR_LINK,
    # KEY_COORDINATOR_SPEED,
    KEY_ROUTER,
    PLATFORMS,
)
from .errors import CannotLoginException
from .router import NokiaRouter

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(seconds=90)

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Nokia component."""
    router = NokiaRouter(hass, entry)
    try:
        if not await router.async_setup():
            raise ConfigEntryNotReady
    except CannotLoginException as ex:
        raise ConfigEntryNotReady from ex

    hass.data.setdefault(DOMAIN, {})

    entry.async_on_unload(entry.add_update_listener(update_listener))

    assert entry.unique_id
    device_registry = dr.async_get(hass)
    device_registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, entry.unique_id)},
        manufacturer="Nokia",
        name=router.device_name,
        model=router.model,
        sw_version=router.firmware_version,
        hw_version=router.hardware_version,
        configuration_url=f"http://{entry.data[CONF_HOST]}/",
    )

    async def async_update_devices() -> bool:
        """Fetch data from the router."""
        if router.track_devices:
            return await router.async_update_device_trackers()
        return False

# TODO future feature?
    # async def async_check_link_status() -> dict[str, Any] | None:
    #     """Fetch data from the router."""
    #     return await router.async_get_link_status()

    # Create update coordinators
    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name=f"{router.device_name} Devices",
        update_method=async_update_devices,
        update_interval=SCAN_INTERVAL,
    )
    # coordinator_speed_test = DataUpdateCoordinator(
    #     hass,
    #     _LOGGER,
    #     name=f"{router.device_name} Speed test",
    #     update_method=async_update_speed_test,
    #     update_interval=SPEED_TEST_INTERVAL,
    # )
    # coordinator_link = DataUpdateCoordinator(
    #     hass,
    #     _LOGGER,
    #     name=f"{router.device_name} Ethernet Link Status",
    #     update_method=async_check_link_status,
    #     update_interval=SCAN_INTERVAL,
    # )

    if router.track_devices:
        await coordinator.async_config_entry_first_refresh()
    # await coordinator_link.async_config_entry_first_refresh()

    hass.data[DOMAIN][entry.entry_id] = {
        KEY_ROUTER: router,
        KEY_COORDINATOR: coordinator,
        # KEY_COORDINATOR_SPEED: coordinator_speed_test,
        # KEY_COORDINATOR_LINK: coordinator_link,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    router = hass.data[DOMAIN][entry.entry_id][KEY_ROUTER]

    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
        if not hass.data[DOMAIN]:
            hass.data.pop(DOMAIN)

    if not router.track_devices:
        router_id = None
        # Remove devices that are no longer tracked
        device_registry = dr.async_get(hass)
        devices = dr.async_entries_for_config_entry(device_registry, entry.entry_id)
        for device_entry in devices:
            if device_entry.via_device_id is None:
                router_id = device_entry.id
                continue  # do not remove the router itself
            device_registry.async_update_device(
                device_entry.id, remove_config_entry_id=entry.entry_id
            )
        # Remove entities that are no longer tracked
        entity_registry = er.async_get(hass)
        entries = er.async_entries_for_config_entry(entity_registry, entry.entry_id)
        for entity_entry in entries:
            if entity_entry.device_id is not router_id:
                entity_registry.async_remove(entity_entry.entity_id)

    return unload_ok


async def update_listener(hass: HomeAssistant, config_entry: ConfigEntry) -> None:
    """Handle options update."""
    await hass.config_entries.async_reload(config_entry.entry_id)


async def async_remove_config_entry_device(
    hass: HomeAssistant, config_entry: ConfigEntry, device_entry: dr.DeviceEntry
) -> bool:
    """Remove a config entry from a device."""
    router = hass.data[DOMAIN][config_entry.entry_id][KEY_ROUTER]

    device_mac = None
    for connection in device_entry.connections:
        if connection[0] == dr.CONNECTION_NETWORK_MAC:
            device_mac = connection[1]
            break

    if device_mac is None:
        return False

    if device_mac not in router.devices:
        return True

    return not router.devices[device_mac]["active"]