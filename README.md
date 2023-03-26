# homeassistant_nokiaxs2426gb_devicetracker

Nokia XS-2426-G-B custom device_tracker component for Home-Assistant.io

## Purpose
The purpose of this custom component for [Home-Assistant](https://home-assistant.io) is to track devices that are connected either wired or wirelessly to a Nokia XS 2426 G B, including clients connected to the guest network.

## Inspired by
This project was inspired by the Experiabox device_tracker custom components that allows [Home-Assistant](https://home-assistant.io) to track devices connected to the Experia Box V10A:

- [homeassistant-experiaboxv10a](https://github.com/FrankZZ/homeassistant-experiabox-v10a) by [FrankZZ](https://github.com/FrankZZ/)

## Setup instructions
### Copying into custom_components folder
Create a directory `custom_components` in your Home-Assistant configuration directory.
Copy the whole [nokiaxs2426gb](./nokiaxs2426gb) folder from this project into the newly created directory `custom_components`.

The result of your copy action(s) should yield a directory structure like so:

```
.homeassistant/
|-- custom_components/
|   |-- nokiaxs2426gb/
|       |-- __init__.py
|       |-- crypto_page.py
|       |-- device_tracker.py
|       |-- manifest.json
```

### Enabling the custom_component
In order to enable this custom device_tracker component, add this code snippet to your Home-Assistant `configuration.yaml` file:

```yaml
device_tracker:
  - platform: nokiaxs2426gb
    host: IPADDRESS
    username: admin
    password: PASSWORD
    interval_seconds: 60
    consider_home: 180
    new_device_defaults:
      track_new_devices: True
```

Please use [secrets](https://www.home-assistant.io/docs/configuration/secrets/) within Home-Assistant to store sensitive data like IPs, usernames and passwords.

