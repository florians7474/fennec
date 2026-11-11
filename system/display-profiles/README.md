# Display profiles

The installer selects a display profile before installing packages. Set
`FENNEC_DISPLAY` to bypass the interactive prompt.

| Profile | Local interface | Use |
|---|---|---|
| `waveshare35c` | SPI framebuffer and calibrated resistive touch | Waveshare 3.5-inch RPi LCD (C) |
| `hdmi` | X11 Chromium kiosk | HDMI-connected display |
| `headless` | None | Access Fennec only from another device on the network |

A profile may provide X11 configuration, a kiosk startup file, boot overlays, and
input calibration. Add a new profile directory under this folder, then add its
installation function and selector entry in `install.sh`.
