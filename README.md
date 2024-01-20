# homeassistant_nokiaxs2426gb_devicetracker

Nokia XS-2426-G-B custom device tracker component for Home-Assistant.io

## Purpose
The purpose of this custom component for [Home-Assistant](https://home-assistant.io) is to track devices that are connected either wired or wirelessly to a Nokia XS 2426 G B, including clients connected to the guest network.

## Inspired by
This project was inspired by the Experiabox device_tracker custom components that allows [Home-Assistant](https://home-assistant.io) to track devices connected to the Experia Box V10A:

- [homeassistant-experiaboxv10a](https://github.com/FrankZZ/homeassistant-experiabox-v10a) by [FrankZZ](https://github.com/FrankZZ/)

The second version was inspired bij the Netgear integration"
- [homeassistant-netgear](https://github.com/home-assistant/core/tree/dev/homeassistant/components/netgear)

## Setup instructions
There are two options, either using HACS or installing manually

### Manually - Copying into custom_components folder
Create a directory `custom_components` in your Home-Assistant configuration directory.
Copy the whole [nokiaxs2426gb](./nokiaxs2426gb) folder from this project into the newly created directory `custom_components`.

The result of your copy action(s) should yield a directory structure like this:

```
.homeassistant/
|-- custom_components/
|   |-- nokiaxs2426gb/
|       |-- __init__.py
|       |-- crypto_page.py
|       |-- device_tracker.py
|       |-- manifest.json
|       |-- ...
```

Reboot Home Assistant

### HACS

Install via HACS Community Store: [http://hacs.xyz/](https://hacs.xyz/)

