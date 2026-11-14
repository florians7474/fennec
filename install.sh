#!/bin/bash
#
# Fennec - Full install on Raspberry Pi OS (64-bit, Bookworm/Trixie).
# Installs Fennec, Pwnagotchi (jayofelony fork), bettercap and pwngrid,
# and sets up the systemd services driven by the launcher.
#
# Usage:  cd ~/fennec && ./install.sh
#
set -e

# --- Markers ---
REPO="$(cd "$(dirname "$0")" && pwd)"      # repo folder (where this script lives)
SYS="$REPO/system"                         # system file templates
USER_NAME="$(whoami)"
USER_HOME="$HOME"
VENV="$USER_HOME/pwnagotchi-venv"
DISPLAY_PROFILE="${FENNEC_DISPLAY:-}"

select_display_profile() {
    if [ -z "$DISPLAY_PROFILE" ]; then
        if [ -t 0 ]; then
            echo ""
            echo "==> Select the display profile:"
            echo "    1) Waveshare 3.5-inch RPi LCD (C) (SPI touchscreen)"
            echo "    2) CUQI 3.5-inch RPM-01 (SPI touchscreen, Waveshare-C compatible)"
            echo "    3) HDMI display (kiosk)"
            echo "    4) Headless (network browser only)"
            read -r -p "Profile [1]: " selection
            case "$selection" in
                ""|1) DISPLAY_PROFILE="waveshare35c" ;;
                2)    DISPLAY_PROFILE="cuqi35" ;;
                3)    DISPLAY_PROFILE="hdmi" ;;
                4)    DISPLAY_PROFILE="headless" ;;
                *)    echo "Invalid display profile."; exit 1 ;;
            esac
        else
            DISPLAY_PROFILE="waveshare35c"
        fi
    fi

    case "$DISPLAY_PROFILE" in
        waveshare35c|cuqi35|hdmi|headless) ;;
        *)
            echo "Unsupported FENNEC_DISPLAY value: $DISPLAY_PROFILE"
            echo "Use waveshare35c, cuqi35, hdmi, or headless."
            exit 1
            ;;
    esac
}

configure_kiosk() {
    local xinit_source="$1"

    sudo cp "$SYS/Xwrapper.config" /etc/X11/Xwrapper.config
    sudo mkdir -p /etc/systemd/system/getty@tty1.service.d
    sudo sed "s/__USER__/$USER_NAME/" "$SYS/getty-autologin.conf" \
        | sudo tee /etc/systemd/system/getty@tty1.service.d/autologin.conf > /dev/null

    cp "$xinit_source" "$USER_HOME/.xinitrc"
    chmod +x "$USER_HOME/.xinitrc"
    if ! grep -q "Fennec: start the kiosk display" "$USER_HOME/.bash_profile" 2>/dev/null; then
        cat "$SYS/bash_profile_kiosk" >> "$USER_HOME/.bash_profile"
    fi
}

configure_waveshare35c() {
    local boot_config overlay_dir driver_dir

    echo "==> Configuring Waveshare 3.5-inch RPi LCD (C)..."
    boot_config=/boot/firmware/config.txt
    [ -f "$boot_config" ] || boot_config=/boot/config.txt
    overlay_dir=/boot/firmware/overlays
    [ -d "$overlay_dir" ] || overlay_dir=/boot/overlays
    driver_dir="$(mktemp -d)"

    wget -q --show-progress -O "$driver_dir/Waveshare35c.zip" \
        https://files.waveshare.com/wiki/common/Waveshare35c.zip
    unzip -q -j "$driver_dir/Waveshare35c.zip" waveshare35c.dtbo -d "$driver_dir"
    sudo install -m 644 "$driver_dir/waveshare35c.dtbo" \
        "$overlay_dir/waveshare35c.dtbo"
    rm -rf "$driver_dir"

    if [ -f "$boot_config" ] && ! grep -q "dtoverlay=waveshare35c" "$boot_config"; then
        sudo tee -a "$boot_config" > /dev/null <<'EOF'

# --- Fennec: Waveshare 3.5-inch RPi LCD (C) ---
disable_splash=1
dtparam=spi=on
dtoverlay=waveshare35c
EOF
    fi

    sudo mkdir -p /etc/X11/xorg.conf.d
    sudo cp "$SYS/display-profiles/waveshare35c/99-fennec-lcd.conf" \
        /etc/X11/xorg.conf.d/99-fennec-lcd.conf
    sudo cp "$SYS/display-profiles/waveshare35c/99-fennec-touch.conf" \
        /etc/X11/xorg.conf.d/99-fennec-touch.conf
    configure_kiosk "$SYS/xinitrc"
}

configure_cuqi35() {
    # The CUQI 3.5-inch RPM-01 is a generic 480x320 SPI touchscreen (ILI9486 +
    # XPT2046) that is driver-compatible with the Waveshare 3.5-inch (C): the
    # same overlay and touch config drive it, verified on hardware.
    echo "==> Configuring CUQI 3.5-inch RPM-01 (Waveshare-C compatible driver)..."
    configure_waveshare35c
}

configure_hdmi() {
    echo "==> Configuring HDMI kiosk display..."
    sudo rm -f /etc/X11/xorg.conf.d/99-fennec-lcd.conf \
        /etc/X11/xorg.conf.d/99-fennec-touch.conf
    configure_kiosk "$SYS/display-profiles/hdmi/xinitrc"
}

select_display_profile
echo "==> Fennec: installing for user '$USER_NAME' (display: $DISPLAY_PROFILE)"

# --- 1. System packages ---
echo "==> Installing apt packages..."
sudo apt update
# tshark (Vigie): we capture as root via sudo, no need for the non-root setuid
# -> preseed the debconf question to avoid the interactive prompt.
echo "wireshark-common wireshark-common/install-setuid boolean false" | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt install -y \
    git python3-venv python3-dev python3-flask python3-msgpack aircrack-ng bettercap golang \
    libpcap-dev libdbus-1-dev libglib2.0-dev pkg-config build-essential \
    liblgpio-dev swig libcap-dev iw tshark dnsmasq \
    john hcxtools nmap qtbase5-dev qt5-qmake libssl-dev \
    chromium curl unzip xserver-xorg xinit xserver-xorg-legacy \
    xserver-xorg-video-fbdev xserver-xorg-input-evdev

# dnsmasq (Vigie DNS capture): Fennec starts its own dnsmasq instance on demand
# during a Watch. Disable the system service so it never holds port 53 and never
# clashes with the on-demand instance.
echo "==> Disabling the system dnsmasq service (Fennec runs its own)..."
sudo systemctl disable --now dnsmasq 2>/dev/null || true

# --- 1b. Enable SPI (required by Bjorn's e-paper display) ---
# Without SPI, /dev/spidev0.0 does not exist and Bjorn crashes on display init.
# Takes effect on the next reboot.
echo "==> Enabling SPI..."
sudo raspi-config nonint do_spi 0 || true

# --- 2. Python environment (venv) + Pwnagotchi ---
if [ ! -d "$VENV" ]; then
    echo "==> Creating the Python venv..."
    python3 -m venv "$VENV"
fi

if [ ! -d "$USER_HOME/pwnagotchi-src" ]; then
    echo "==> Cloning Pwnagotchi (jayofelony fork)..."
    git clone https://github.com/jayofelony/pwnagotchi.git "$USER_HOME/pwnagotchi-src"
fi

# GPS plugin fix: it tries to replace ".pcapng" while bettercap saves captures
# as ".pcap". Without this fix the plugin overwrites the handshake with the
# position JSON instead of writing a .gps.json next to it. Patch the source
# before installing it into the venv.
sed -i 's/\.pcapng/.pcap/' "$USER_HOME/pwnagotchi-src/pwnagotchi/plugins/default/gps.py"

echo "==> Installing Pwnagotchi into the venv (long)..."
"$VENV/bin/pip" install --prefer-binary "$USER_HOME/pwnagotchi-src"
"$VENV/bin/pip" install python-prctl

# --- 3. Build pwngrid ---
if [ ! -f /usr/local/bin/pwngrid ]; then
    echo "==> Building pwngrid..."
    if [ ! -d "$USER_HOME/pwngrid-src" ]; then
        git clone https://github.com/jayofelony/pwngrid.git "$USER_HOME/pwngrid-src"
    fi
    ( cd "$USER_HOME/pwngrid-src" && make )
    sudo cp "$USER_HOME/pwngrid-src/build/pwngrid" /usr/local/bin/
fi

# --- 4. Generated bettercap password ---
BC_PASS="$(openssl rand -hex 12)"
echo "==> bettercap password generated."

# --- 5. Pwnagotchi config + caplet ---
echo "==> Setting up the Pwnagotchi config..."
sudo mkdir -p /etc/pwnagotchi
sudo sed "s/__BETTERCAP_PASS__/$BC_PASS/" "$SYS/config.toml" \
    | sudo tee /etc/pwnagotchi/config.toml > /dev/null
sudo sed "s/__BETTERCAP_PASS__/$BC_PASS/" "$SYS/pwnagotchi-auto.cap" \
    | sudo tee /etc/pwnagotchi/pwnagotchi-auto.cap > /dev/null

# --- 6. Launcher scripts ---
echo "==> Installing the launcher scripts..."
sudo cp "$SYS/fennec-bettercap" /usr/local/bin/fennec-bettercap
sudo cp "$SYS/fennec-pwngrid"   /usr/local/bin/fennec-pwngrid
sudo cp "$SYS/fennec-clear-handshakes" /usr/local/bin/fennec-clear-handshakes
sudo cp "$SYS/fennec-netscan" /usr/local/bin/fennec-netscan
sudo cp "$SYS/fennec-monitor" /usr/local/bin/fennec-monitor
sudo cp "$SYS/fennec-dns-force" /usr/local/bin/fennec-dns-force
sudo cp "$SYS/fennec-pwna-iface" /usr/local/bin/fennec-pwna-iface
sudo cp "$SYS/fennec-wifi-connect" /usr/local/bin/fennec-wifi-connect
sudo cp "$SYS/fennec-wifi-disconnect" /usr/local/bin/fennec-wifi-disconnect
sudo cp "$SYS/fennec-wardrive" /usr/local/bin/fennec-wardrive
sudo chmod +x /usr/local/bin/fennec-bettercap /usr/local/bin/fennec-pwngrid /usr/local/bin/fennec-clear-handshakes /usr/local/bin/fennec-netscan /usr/local/bin/fennec-monitor /usr/local/bin/fennec-dns-force /usr/local/bin/fennec-pwna-iface /usr/local/bin/fennec-wifi-connect /usr/local/bin/fennec-wifi-disconnect /usr/local/bin/fennec-wardrive

# --- 7. systemd services (with venv substitution) ---
echo "==> Installing the systemd services..."
for svc in bettercap pwngrid-peer pwnagotchi fennec-wardrive; do
    sudo sed "s#__VENV__#$VENV#g" "$SYS/$svc.service" \
        | sudo tee "/etc/systemd/system/$svc.service" > /dev/null
done
sudo systemctl daemon-reload

# --- 8. sudoers rule (with user substitution) ---
echo "==> Setting up Fennec's sudo rights..."
sudo sed "s/__USER__/$USER_NAME/" "$SYS/fennec.sudoers" \
    | sudo tee /etc/sudoers.d/fennec > /dev/null
sudo chmod 440 /etc/sudoers.d/fennec

# --- Bjorn (LAN scan/attack) ---
echo "==> Installing Bjorn..."

# Source code (infinition/Bjorn)
if [ ! -d "$USER_HOME/Bjorn" ]; then
    git clone https://github.com/infinition/Bjorn.git "$USER_HOME/Bjorn"
fi

# Bjorn web server patch: keep port 8000 and allow address reuse. Without this,
# a Stop/Start leaves the port in TIME_WAIT, Bjorn jumps to 8001 and the page
# becomes unreachable from the Fennec tile.
if ! grep -q "allow_reuse_address = True" "$USER_HOME/Bjorn/webapp.py"; then
    sed -i '/^import socketserver$/a socketserver.TCPServer.allow_reuse_address = True' "$USER_HOME/Bjorn/webapp.py"
fi
sed -i 's/^\( *\)self.port += 1/\1__import__("time").sleep(2)/' "$USER_HOME/Bjorn/webapp.py"

# Headless e-paper: Bjorn runs web-only here (its panel's GPIO pins are taken by
# the Fennec touchscreen). Replace its e-paper helper with a no-op stand-in so it
# never claims GPIO and never crashes with "GPIO busy".
cp "$SYS/bjorn-epd_helper.py" "$USER_HOME/Bjorn/epd_helper.py"

# Dedicated venv + Python dependencies
if [ ! -d "$USER_HOME/bjorn-venv" ]; then
    python3 -m venv "$USER_HOME/bjorn-venv"
fi
"$USER_HOME/bjorn-venv/bin/pip" install --prefer-binary -r "$SYS/bjorn-requirements.txt"

# Web console script (path adapted to the user)
sudo sed "s#__HOME__#$USER_HOME#g" "$SYS/fennec-bjorn-console" \
    | sudo tee /usr/local/bin/fennec-bjorn-console > /dev/null
sudo chmod +x /usr/local/bin/fennec-bjorn-console

# Bjorn systemd services (path adapted)
for svc in bjorn bjorn-console; do
    sudo sed "s#__HOME__#$USER_HOME#g" "$SYS/$svc.service" \
        | sudo tee "/etc/systemd/system/$svc.service" > /dev/null
done
sudo systemctl daemon-reload

# --- 9. Raton: WPA cracking engine (routerkeygen + wordlists) ---
echo "==> Setting up Raton (WPA cracking)..."

# routerkeygen-cli (factory keys): not in apt, build from source
if [ ! -f /usr/local/bin/routerkeygen-cli ]; then
    echo "==> Building routerkeygen-cli..."
    if [ ! -d "$USER_HOME/routerkeygen-src" ]; then
        git clone https://github.com/routerkeygen/routerkeygenPC.git "$USER_HOME/routerkeygen-src"
    fi
    ( cd "$USER_HOME/routerkeygen-src/cli" && qmake && make )
    sudo cp "$USER_HOME/routerkeygen-src/cli/routerkeygen-cli" /usr/local/bin/
fi

# Wordlists (in /usr/share/wordlists)
sudo mkdir -p /usr/share/wordlists

# rockyou (downloaded from SecLists, extracted into /usr/share/wordlists)
if [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    sudo wget -O /tmp/rockyou.txt.tar.gz \
        https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz
    sudo tar -xzf /tmp/rockyou.txt.tar.gz -C /usr/share/wordlists/
    sudo rm -f /tmp/rockyou.txt.tar.gz
    sudo chown root:root /usr/share/wordlists/rockyou.txt
    sudo chmod 644 /usr/share/wordlists/rockyou.txt
fi

# 10k common passwords (SecLists)
if [ ! -f /usr/share/wordlists/10k-common.txt ]; then
    sudo wget -O /usr/share/wordlists/10k-common.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt
fi

# real cracked WPA keys (SecLists)
if [ ! -f /usr/share/wordlists/probable-wpa-top4800.txt ]; then
    sudo wget -O /usr/share/wordlists/probable-wpa-top4800.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt
fi

# --- 10. Automatic Wi-Fi reconnection (nomadic use) ---
echo "==> Setting up automatic Wi-Fi reconnection..."
sudo mkdir -p /etc/NetworkManager/conf.d
sudo cp "$SYS/wifi-retry.conf" /etc/NetworkManager/conf.d/wifi-retry.conf
sudo systemctl reload NetworkManager || true

# --- 11. Fennec as a systemd service ---
# Fennec runs continuously (the kiosk and the touchscreen connect to it).
echo "==> Installing the Fennec service..."
sudo sed -e "s/__USER__/$USER_NAME/g" -e "s#__REPO__#$REPO#g" "$SYS/fennec.service" \
    | sudo tee /etc/systemd/system/fennec.service > /dev/null
sudo systemctl daemon-reload
sudo systemctl enable fennec

# --- 12. Display profile ---
case "$DISPLAY_PROFILE" in
    waveshare35c)
        configure_waveshare35c
        ;;
    cuqi35)
        configure_cuqi35
        ;;
    hdmi)
        configure_hdmi
        ;;
    headless)
        echo "==> Headless mode selected; skipping local kiosk configuration."
        ;;
esac
sudo systemctl daemon-reload

echo ""
echo "==> Installation complete."
if [ "$DISPLAY_PROFILE" = "headless" ]; then
    echo "    Fennec is available on the local network: http://<Pi-IP>:5000/"
else
    echo "    Reboot once to enable the selected display profile: sudo reboot"
    echo "    Fennec will start automatically after reboot."
fi
