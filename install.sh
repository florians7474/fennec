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
# Image-build mode: when building a distributable disk image (in a chroot with no
# running systemd), services are only enabled, never started, and the first-boot
# secret generation is left for the device's real first boot.
IMAGE_BUILD="${FENNEC_IMAGE_BUILD:-}"

# The lock keeps fresh installations reproducible. Generated source folders are
# checked out at their recorded commit on every installer run.
# shellcheck source=system/sources.lock
source "$SYS/sources.lock"

clone_pinned() {
    local name="$1" repository="$2" ref="$3" destination="$4" actual

    if [ ! -d "$destination/.git" ]; then
        if [ -e "$destination" ]; then
            echo "Cannot prepare $name: $destination exists but is not a Git checkout."
            exit 1
        fi
        echo "==> Cloning $name at $ref..."
        git clone --no-checkout "$repository" "$destination"
    fi

    git -C "$destination" fetch --quiet --depth=1 origin "$ref"
    git -C "$destination" checkout --quiet --detach --force FETCH_HEAD
    actual="$(git -C "$destination" rev-parse HEAD)"
    if [ "$actual" != "$ref" ]; then
        echo "$name resolved to $actual instead of the locked commit $ref."
        exit 1
    fi
}

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

    # The kiosk boots to the console, auto-logs in on tty1 and runs startx (see
    # the getty auto-login override and bash_profile below). Force console boot
    # and remove any display manager, otherwise a desktop session owns the screen
    # and the kiosk never starts (the system stops at graphical.target).
    sudo systemctl set-default multi-user.target
    sudo systemctl disable lightdm.service 2>/dev/null || true
    # Force the tty1 getty to start at boot: it is what auto-logs in and runs
    # startx for the kiosk, and it does not always come up on its own.
    sudo systemctl enable getty@tty1.service

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
        "$WAVESHARE35C_ARCHIVE_URL"
    echo "$WAVESHARE35C_ARCHIVE_SHA256  $driver_dir/Waveshare35c.zip" | sha256sum -c -
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
    liblgpio-dev swig libcap-dev iw tshark dnsmasq hostapd \
    john hcxtools hcxdumptool nmap python3-netifaces python3-aioquic qtbase5-dev qt5-qmake libssl-dev \
    zlib1g-dev libbz2-dev libgmp-dev \
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

clone_pinned "Pwnagotchi" "$PWNAGOTCHI_REPOSITORY" "$PWNAGOTCHI_REF" "$USER_HOME/pwnagotchi-src"

# GPS plugin fix: it tries to replace ".pcapng" while bettercap saves captures
# as ".pcap". Without this fix the plugin overwrites the handshake with the
# position JSON instead of writing a .gps.json next to it. Patch the source
# before installing it into the venv.
sed -i 's/\.pcapng/.pcap/' "$USER_HOME/pwnagotchi-src/pwnagotchi/plugins/default/gps.py"

echo "==> Installing Pwnagotchi into the venv (long)..."
# Install Pwnagotchi WITHOUT its reinforcement-learning stack (torch, torchvision,
# stable_baselines3, shimmy) — ~2.5 GB of CUDA wheels that are useless on the Pi.
# The AI is disabled in config.toml and ai.load() returns before importing them,
# so they are never needed. Install the package with --no-deps, then its runtime
# dependencies minus the AI ones (their own sub-dependencies are pulled normally).
"$VENV/bin/pip" install --prefer-binary --no-deps "$USER_HOME/pwnagotchi-src"
"$VENV/bin/pip" install --prefer-binary \
    Pillow PyYAML rpi.lgpio dbus-python file-read-backwards flask flask-cors \
    flask-wtf gast gpiozero inky pycryptodome pydrive2 python-dateutil requests \
    rpi_hardware_pwm scapy smbus2 spidev toml tweepy websockets python-prctl

# --- 3. Build pwngrid ---
if [ ! -f /usr/local/bin/pwngrid ]; then
    echo "==> Building pwngrid..."
    clone_pinned "pwngrid" "$PWNGRID_REPOSITORY" "$PWNGRID_REF" "$USER_HOME/pwngrid-src"
    ( cd "$USER_HOME/pwngrid-src" && make )
    sudo cp "$USER_HOME/pwngrid-src/build/pwngrid" /usr/local/bin/
fi

# --- 5. Pwnagotchi config + caplet ---
# The bettercap password is NOT generated here: the files keep the
# __BETTERCAP_PASS__ placeholder and the fennec-firstboot service fills it with a
# fresh per-device secret on first boot. That way a shared disk image never ships
# a baked-in password (see step 6b and fennec-firstboot).
echo "==> Setting up the Pwnagotchi config..."
sudo mkdir -p /etc/pwnagotchi
sudo cp "$SYS/config.toml" /etc/pwnagotchi/config.toml
sudo cp "$SYS/pwnagotchi-auto.cap" /etc/pwnagotchi/pwnagotchi-auto.cap

# --- 5b. First-boot secrets service ---
# Generates per-device secrets (currently the bettercap password) the first time
# the system boots, so a pre-built disk image carries no baked-in secret. The
# service is idempotent: once the placeholder is filled it does nothing.
echo "==> Installing the first-boot secrets service..."
sudo cp "$SYS/fennec-firstboot" /usr/local/bin/fennec-firstboot
sudo chmod +x /usr/local/bin/fennec-firstboot
sudo cp "$SYS/fennec-firstboot.service" /etc/systemd/system/fennec-firstboot.service
sudo systemctl daemon-reload || true
sudo systemctl enable fennec-firstboot
# Run it once now so a direct install is immediately functional (no reboot
# needed to get the bettercap password). On a disk-image build this is skipped so
# the image keeps the placeholder and each flashed card generates its own secret.
if [ -z "$IMAGE_BUILD" ]; then
    sudo systemctl start fennec-firstboot
fi

# --- 6. Launcher scripts ---
echo "==> Installing the launcher scripts..."
sudo cp "$SYS/fennec-bettercap" /usr/local/bin/fennec-bettercap
sudo cp "$SYS/fennec-pwngrid"   /usr/local/bin/fennec-pwngrid
sudo cp "$SYS/fennec-clear-handshakes" /usr/local/bin/fennec-clear-handshakes
sudo cp "$SYS/fennec-netscan" /usr/local/bin/fennec-netscan
sudo cp "$SYS/fennec-monitor" /usr/local/bin/fennec-monitor
sudo cp "$SYS/fennec-wifi-scan" /usr/local/bin/fennec-wifi-scan
sudo cp "$SYS/fennec-dns-force" /usr/local/bin/fennec-dns-force
sudo cp "$SYS/fennec-pwna-iface" /usr/local/bin/fennec-pwna-iface
sudo cp "$SYS/fennec-wifi-connect" /usr/local/bin/fennec-wifi-connect
sudo cp "$SYS/fennec-wifi-disconnect" /usr/local/bin/fennec-wifi-disconnect
sudo cp "$SYS/fennec-wardrive" /usr/local/bin/fennec-wardrive
sudo cp "$SYS/fennec-mirage-ap" /usr/local/bin/fennec-mirage-ap
sudo cp "$SYS/fennec-mirage-portal" /usr/local/bin/fennec-mirage-portal
sudo cp "$SYS/fennec-mirage-deauth" /usr/local/bin/fennec-mirage-deauth
sudo cp "$SYS/fennec-mirage-portal-manage" /usr/local/bin/fennec-mirage-portal-manage
sudo cp "$SYS/fennec-mole" /usr/local/bin/fennec-mole
sudo cp "$SYS/fennec-mole-relay" /usr/local/bin/fennec-mole-relay
sudo cp "$SYS/fennec-scout" /usr/local/bin/fennec-scout
sudo cp "$SYS/fennec-scout-poll.py" /usr/local/bin/fennec-scout-poll
sudo chmod +x /usr/local/bin/fennec-scout-poll
sudo chmod +x /usr/local/bin/fennec-bettercap /usr/local/bin/fennec-pwngrid /usr/local/bin/fennec-clear-handshakes /usr/local/bin/fennec-netscan /usr/local/bin/fennec-monitor /usr/local/bin/fennec-wifi-scan /usr/local/bin/fennec-dns-force /usr/local/bin/fennec-pwna-iface /usr/local/bin/fennec-wifi-connect /usr/local/bin/fennec-wifi-disconnect /usr/local/bin/fennec-wardrive /usr/local/bin/fennec-mirage-ap /usr/local/bin/fennec-mirage-portal /usr/local/bin/fennec-mirage-deauth /usr/local/bin/fennec-mirage-portal-manage /usr/local/bin/fennec-mole /usr/local/bin/fennec-mole-relay /usr/local/bin/fennec-scout /usr/local/bin/fennec-scout-poll

# Mirage portal: refresh the shipped default while preserving custom portals.
sudo mkdir -p /opt/fennec-mirage/default-portal /opt/fennec-mirage/portal
sudo rm -rf /opt/fennec-mirage/default-portal/*
sudo cp -a "$SYS/mirage-portal/." /opt/fennec-mirage/default-portal/

# Mirage portal library: built-in themes the user can apply in one tap.
sudo mkdir -p /opt/fennec-mirage/portals
sudo rm -rf /opt/fennec-mirage/portals/*
sudo cp -a "$SYS/mirage-portals/." /opt/fennec-mirage/portals/
if [ ! -f /opt/fennec-mirage/portal/index.html ]; then
    sudo cp -a /opt/fennec-mirage/default-portal/. /opt/fennec-mirage/portal/
    echo '{"label":"Default portal","kind":"default"}' | sudo tee /opt/fennec-mirage/portal.json > /dev/null
elif [ ! -f /opt/fennec-mirage/portal.json ]; then
    if cmp -s /opt/fennec-mirage/portal/index.html /opt/fennec-mirage/default-portal/index.html; then
        echo '{"label":"Default portal","kind":"default"}' | sudo tee /opt/fennec-mirage/portal.json > /dev/null
    else
        echo '{"label":"Custom portal","kind":"custom"}' | sudo tee /opt/fennec-mirage/portal.json > /dev/null
    fi
elif grep -q '"kind"[[:space:]]*:[[:space:]]*"default"' /opt/fennec-mirage/portal.json; then
    sudo rm -rf /opt/fennec-mirage/portal/*
    sudo cp -a /opt/fennec-mirage/default-portal/. /opt/fennec-mirage/portal/
fi
sudo chmod -R a+rX /opt/fennec-mirage

# --- 7. systemd services (with venv substitution) ---
echo "==> Installing the systemd services..."
for svc in bettercap pwngrid-peer pwnagotchi fennec-wardrive; do
    sudo sed "s#__VENV__#$VENV#g" "$SYS/$svc.service" \
        | sudo tee "/etc/systemd/system/$svc.service" > /dev/null
done
sudo cp "$SYS/fennec-mirage.service" /etc/systemd/system/fennec-mirage.service
sudo cp "$SYS/fennec-mirage-deauth.service" /etc/systemd/system/fennec-mirage-deauth.service
sudo cp "$SYS/fennec-mole.service" /etc/systemd/system/fennec-mole.service
sudo cp "$SYS/fennec-mole-relay.service" /etc/systemd/system/fennec-mole-relay.service
sudo cp "$SYS/fennec-scout.service" /etc/systemd/system/fennec-scout.service
sudo systemctl daemon-reload || true

# --- 8. sudoers rule (with user substitution) ---
echo "==> Setting up Fennec's sudo rights..."
sudo sed "s/__USER__/$USER_NAME/" "$SYS/fennec.sudoers" \
    | sudo tee /etc/sudoers.d/fennec > /dev/null
sudo chmod 440 /etc/sudoers.d/fennec

# --- Bjorn (LAN scan/attack) ---
echo "==> Installing Bjorn..."

# Source code (infinition/Bjorn)
clone_pinned "Bjorn" "$BJORN_REPOSITORY" "$BJORN_REF" "$USER_HOME/Bjorn"

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
sudo systemctl daemon-reload || true

# --- 9. Raton: WPA cracking engine (routerkeygen + wordlists) ---
echo "==> Setting up Raton (WPA cracking)..."

# routerkeygen-cli (factory keys): not in apt, build from source
if [ ! -f /usr/local/bin/routerkeygen-cli ]; then
    echo "==> Building routerkeygen-cli..."
    clone_pinned "routerkeygen" "$ROUTERKEYGEN_REPOSITORY" "$ROUTERKEYGEN_REF" "$USER_HOME/routerkeygen-src"
    # Trixie can select Qt6 for plain qmake, while routerkeygen-cli needs Qt5.
    # Prefer the default when it is Qt5, then fall back to qtchooser's Qt5 selector
    # and finally to Qt5's direct binary.
    QMAKE_CMD=(qmake)
    if ! qmake -v 2>/dev/null | grep -q "Qt version 5"; then
        if qmake -qt5 -v 2>/dev/null | grep -q "Qt version 5"; then
            QMAKE_CMD=(qmake -qt5)
        elif [ -x /usr/lib/qt5/bin/qmake ]; then
            QMAKE_CMD=(/usr/lib/qt5/bin/qmake)
        else
            echo "Qt5 qmake was not found; cannot build routerkeygen-cli."
            exit 1
        fi
    fi
    ( cd "$USER_HOME/routerkeygen-src/cli" && "${QMAKE_CMD[@]}" && make )
    sudo cp "$USER_HOME/routerkeygen-src/cli/routerkeygen-cli" /usr/local/bin/
fi

# Wordlists (in /usr/share/wordlists)
sudo mkdir -p /usr/share/wordlists

# rockyou (downloaded from SecLists, extracted into /usr/share/wordlists)
if [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    sudo wget -O /tmp/rockyou.txt.tar.gz \
        https://raw.githubusercontent.com/danielmiessler/SecLists/$SECLISTS_REF/Passwords/Leaked-Databases/rockyou.txt.tar.gz
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

# --- 9b. Mole: drop-box credential capture (Responder + John jumbo) ---
# Responder isn't packaged on Raspberry Pi OS (it's a Kali package), so install it
# from source (its runtime deps python3-netifaces and python3-aioquic come from apt
# above, along with nmap and hcxtools used by Mole).
echo "==> Setting up Mole (Responder)..."
if [ ! -d /opt/Responder/.git ]; then
    sudo rm -rf /opt/Responder
    sudo git clone --no-checkout "$RESPONDER_REPOSITORY" /opt/Responder
fi
sudo git -C /opt/Responder fetch --quiet --depth=1 origin "$RESPONDER_REF"
sudo git -C /opt/Responder checkout --quiet --detach --force FETCH_HEAD
sudo chmod -R a+rX /opt/Responder

# John the Ripper "jumbo": the Debian 'john' package lacks the netntlmv2 format
# Mole needs to crack captured Windows hashes, so build the jumbo edition from
# source to /opt/john (binary at /opt/john/run/john).
echo "==> Building John the Ripper (jumbo) for Mole (long)..."
if [ ! -x /opt/john/run/john ]; then
    if [ ! -d /opt/john/.git ]; then
        sudo rm -rf /opt/john
        sudo git clone --no-checkout "$JOHN_REPOSITORY" /opt/john
    fi
    sudo git -C /opt/john fetch --quiet --depth=1 origin "$JOHN_REF"
    sudo git -C /opt/john checkout --quiet --detach --force FETCH_HEAD
    ( cd /opt/john/src && sudo ./configure && sudo make -s -j"$(nproc)" )
fi
sudo chmod -R a+rX /opt/john

# Mole active relay (phase 2): impacket's ntlmrelayx + mitm6, in a dedicated venv
# so they stay isolated from the system and the Pwnagotchi venv.
echo "==> Installing Mole relay tools (impacket, mitm6)..."
if [ ! -x /opt/mole-venv/bin/mitm6 ]; then
    sudo python3 -m venv /opt/mole-venv
    sudo /opt/mole-venv/bin/pip install --quiet --upgrade pip
    sudo /opt/mole-venv/bin/pip install --quiet impacket mitm6
fi
sudo chmod -R a+rX /opt/mole-venv

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
sudo systemctl daemon-reload || true
# Image build: enable only (the service starts on the device's first real boot).
if [ -n "$IMAGE_BUILD" ]; then
    sudo systemctl enable fennec
else
    sudo systemctl enable --now fennec
fi

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
sudo systemctl daemon-reload || true

echo ""
echo "==> Installation complete."
if [ "$DISPLAY_PROFILE" = "headless" ]; then
    echo "    Fennec is available on the local network: http://<Pi-IP>:5000/"
else
    echo "    Reboot once to enable the selected display profile: sudo reboot"
    echo "    Fennec will start automatically after reboot."
fi
