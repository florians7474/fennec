# epd_helper.py - headless stand-in installed by Fennec.
#
# Fennec runs Bjorn web-only: its output is shown in the Bjorn tile, not on an
# e-paper panel. The real e-paper driver claims GPIO pins that the Fennec
# touchscreen already uses, so loading it aborts with "GPIO busy". This no-op
# helper gives Bjorn's display code the same interface without touching GPIO.

import logging

logger = logging.getLogger(__name__)

# Geometry of the panel Bjorn targets by default (Waveshare 2.13" V4). Bjorn
# reads width/height from here to size the images it renders for the web view.
_WIDTH = 122
_HEIGHT = 250


class _DummyPanel:
    width = _WIDTH
    height = _HEIGHT
    FULL_UPDATE = 0
    PART_UPDATE = 1
    sleep = 0

    def init(self, *args, **kwargs):
        return 0

    def getbuffer(self, image):
        return image

    def display(self, *args, **kwargs):
        pass

    def displayPartial(self, *args, **kwargs):
        pass

    def Clear(self, *args, **kwargs):
        pass

    def Dev_exit(self, *args, **kwargs):
        pass

    def module_exit(self, *args, **kwargs):
        pass


class EPDHelper:
    def __init__(self, epd_type=None):
        self.epd_type = epd_type
        self.epd = _DummyPanel()

    def init_full_update(self):
        pass

    def init_partial_update(self):
        pass

    def display_partial(self, image):
        pass

    def clear(self):
        pass
