# Reproducibility Guide

This document explains how to reproduce the Commodity SBC GOOSE Security Testbed
from bare hardware up to the point where all C components are built with `make`.

It covers:

- Hardware and network layout
- Installing Ubuntu on each LattePanda
- Basic package installation
- Management network setup over Wi-Fi
- GOOSE LAN configuration on wired interfaces
- BITW network configuration (two interface setup)
- Attacker virtual machine setup
- Installing required libraries and tools
- Cloning this repository
- Building the publisher, subscriber, BITW, and logger binaries

It does not cover running experiments, PTP services, loggers, or attacks. Those
are described in the main README and other project notes.

## 1. Hardware

You will need:

- 3 LattePanda single board computers
  - Each with onboard Ethernet (for GOOSE LAN)
  - Each with onboard Wi-Fi (for management)
- 1 USB to Ethernet adapter for the BITW node
- 1 Cisco Catalyst 1200 series Ethernet switch (or similar unmanaged switch)
- 1 Windows laptop to host the attacker virtual machine
- 1 USB thumb drive (8 GB or larger) to install Ubuntu
- HDMI monitor and USB keyboard/mouse (for initial setup on each LattePanda)
- Several Ethernet cables

Roles:

- Publisher LattePanda
- BITW LattePanda
- Subscriber LattePanda
- Attacker VM running on the Windows laptop

## 2. Network addressing

This guide assumes the following addresses. You can change them, but keep the
mapping consistent across all configuration files.

Management (Wi-Fi) network (example):

- Publisher Wi-Fi:   192.168.2.102
- BITW Wi-Fi:        192.168.2.103
- Subscriber Wi-Fi:  192.168.2.104
- Gateway (router):  192.168.2.1

GOOSE LAN networks:

Side A (between Publisher, BITW, and Attacker VM):

- Publisher wired:   10.0.0.2
- BITW side A:       10.0.0.3
- Attacker VM:       10.0.0.5

Side B (between BITW and Subscriber):

- BITW side B:       10.0.1.3
- Subscriber wired:  10.0.1.4

All wired devices connect to the Cisco switch, and the BITW node forwards or
drops GOOSE traffic between side A and side B according to its policy.

## 3. Install Ubuntu on each LattePanda

Perform these steps for all three LattePandas (Publisher, BITW, Subscriber).

1. On any existing computer, download the Ubuntu 24.04 LTS ISO.
2. Use a tool such as Rufus or balenaEtcher to write the ISO to a USB thumb drive.
3. Connect the USB thumb drive, monitor, keyboard, and mouse to a LattePanda.
4. Power on the LattePanda and open the boot menu (commonly F7 or DEL).
5. Select the USB device and choose "Install Ubuntu" when prompted.
6. Install Ubuntu to the internal storage.
7. Create a user account that matches the node role if desired:
   - publisher
   - bitw
   - subscriber
8. Complete the installer and reboot into the installed Ubuntu.
9. Repeat the process for each LattePanda.

## 4. Base system configuration on LattePandas

For each LattePanda:

1. Log in locally or via a temporary network.
2. Update packages:

```bash
sudo apt update
sudo apt upgrade -y
```

3. Install required base packages:

```bash
sudo apt install -y \
  build-essential git cmake pkg-config \
  libpcap-dev libssl-dev libjson-c-dev \
  linuxptp ethtool \
  net-tools tcpdump
```

These packages are used to:

- Compile C code (publisher, subscriber, BITW, loggers)
- Link against libpcap, OpenSSL, JSON
- Provide PTP tools (linuxptp)

## 5. Configure Wi-Fi management network

Use Wi-Fi for SSH and management so the wired interfaces are free for GOOSE.

On each LattePanda:

1. Identify the Wi-Fi interface (usually `wlo1`):

```bash
ip link
```

2. Create or edit a netplan file, for example `/etc/netplan/01-network-manager-all.yaml`.

On the Publisher LattePanda, the file should look similar to:

```yaml
network:
  version: 2
  renderer: NetworkManager

  wifis:
    wlo1:
      dhcp4: no
      addresses: [192.168.2.102/24]
      gateway4: 192.168.2.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
      access-points:
        "YOUR_SSID_HERE":
          password: "YOUR_WIFI_PASSWORD_HERE"
```

On the BITW LattePanda, only the address changes:

```yaml
  wifis:
    wlo1:
      dhcp4: no
      addresses: [192.168.2.103/24]
      gateway4: 192.168.2.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
      access-points:
        "YOUR_SSID_HERE":
          password: "YOUR_WIFI_PASSWORD_HERE"
```

On the Subscriber LattePanda:

```yaml
  wifis:
    wlo1:
      dhcp4: no
      addresses: [192.168.2.104/24]
      gateway4: 192.168.2.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
      access-points:
        "YOUR_SSID_HERE":
          password: "YOUR_WIFI_PASSWORD_HERE"
```

3. Apply the configuration:

```bash
sudo netplan apply
```

4. Verify connectivity:

```bash
ping -c 3 192.168.2.1
```

### 5.2 Alternative: configure Wi-Fi using nmcli

Instead of defining Wi-Fi in netplan, you can configure it directly with
NetworkManager and `nmcli`. For example, on the publisher:

```bash
sudo nmcli connection add type wifi ifname wlo1 con-name panda-wifi ssid "YOUR_SSID_HERE"

sudo nmcli connection modify panda-wifi \
    wifi-sec.key-mgmt wpa-psk \
    wifi-sec.psk "YOUR_WIFI_PASSWORD_HERE"

sudo nmcli connection modify panda-wifi \
    ipv4.addresses 192.168.2.102/24 \
    ipv4.gateway 192.168.2.1 \
    ipv4.dns "8.8.8.8 1.1.1.1" \
    ipv4.method manual

sudo nmcli connection up panda-wifi
```

To delete an old Wi-Fi profile:

```bash
nmcli connection show
sudo nmcli connection delete "OLD_CONNECTION_NAME"
```

In this repository, netplan is used as the primary source of truth, but these
commands describe the underlying NetworkManager state that was used when
initially debugging Wi-Fi.

## 6. Enable SSH on LattePandas

On each LattePanda:

```bash
sudo apt install -y openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh
sudo systemctl status ssh
```

From another machine, you should be able to connect:

```bash
ssh publisher@192.168.2.102
ssh bitw@192.168.2.103
ssh subscriber@192.168.2.104
```

Adjust hostnames and addresses if you chose different values.

## 7. Configure GOOSE LAN on Publisher and Subscriber

The wired interface on each LattePanda carries GOOSE and PTP traffic.

1. Identify the wired interface, usually `enp1s0`:

```bash
ip link
```

2. Edit the same netplan file `/etc/netplan/01-network-manager-all.yaml` on
each LattePanda to add the Ethernet configuration.

On the Publisher LattePanda, the file should contain both Wi-Fi and Ethernet,
for example:

```yaml
network:
  version: 2
  renderer: NetworkManager

  wifis:
    wlo1:
      dhcp4: no
      addresses: [192.168.2.102/24]
      gateway4: 192.168.2.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
      access-points:
        "YOUR_SSID_HERE":
          password: "YOUR_WIFI_PASSWORD_HERE"

  ethernets:
    enp1s0:
      dhcp4: no
      addresses: [10.0.0.2/24]
```

On the Subscriber LattePanda:

```yaml
network:
  version: 2
  renderer: NetworkManager

  wifis:
    wlo1:
      dhcp4: no
      addresses: [192.168.2.104/24]
      gateway4: 192.168.2.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
      access-points:
        "YOUR_SSID_HERE":
          password: "YOUR_WIFI_PASSWORD_HERE"

  ethernets:
    enp1s0:
      dhcp4: no
      addresses: [10.0.1.4/24]
```

3. Apply netplan on both:

```bash
sudo netplan apply
```

4. Test connectivity over the wired networks.

From Publisher to Subscriber side:

```bash
ping -c 3 10.0.1.4
```

From Subscriber to Publisher side:

```bash
ping -c 3 10.0.0.2
```

## 8. Configure BITW interfaces

The BITW node has:

- Onboard wired NIC, for example `enp1s0`
- USB wired NIC, for example `enx4cea4162b088`
- Wi-Fi interface `wlo1` for management SSH

Each wired NIC has its own static IP on a different subnet.

Example `/etc/netplan/01-network-manager-all.yaml` on the BITW node:

```yaml
network:
  version: 2
  renderer: NetworkManager

  ethernets:
    enp1s0:            # side A toward publisher and attacker
      dhcp4: no
      addresses: [10.0.0.3/24]

    enx4cea4162b088:   # side B toward subscriber
      dhcp4: no
      addresses: [10.0.1.3/24]

  wifis:
    wlo1:
      dhcp4: no
      addresses: [192.168.2.103/24]
      gateway4: 192.168.2.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
      access-points:
        "YOUR_SSID_HERE":
          password: "YOUR_WIFI_PASSWORD_HERE"
```

Apply the configuration:

```bash
sudo netplan apply
```

Then verify connectivity.

From BITW to Publisher and Attacker on side A:

```bash
ping -c 3 10.0.0.2
ping -c 3 10.0.0.5
```

From BITW to Subscriber on side B:

```bash
ping -c 3 10.0.1.4
```

From the Publisher and Attacker side, you should be able to ping 10.0.0.3.
From the Subscriber side, you should be able to ping 10.0.1.3.

The BITW engine will read GOOSE frames from both `enp1s0` and
`enx4cea4162b088` and forward or drop them according to its policy.


## 9. Set up the attacker virtual machine

The attacker runs on a Linux machine or a Linux VM in bridged mode on a Windows laptop so it shares
the same Layer 2 segment as the GOOSE LAN.

Inside the Linux machine / VM:

1. Identify the bridged interface, for example `enp0s3`:

```bash
ip link
```

2. Configure a static IP on the GOOSE LAN, for example `/etc/netplan/10-goose.yaml`:

```yaml
network:
  version: 2
  renderer: NetworkManager

  ethernets:
    enp0s3:
      dhcp4: no
      addresses:
        - 10.0.0.5/24
```

3. Apply:

```bash
sudo netplan apply
```

4. Test connectivity:

```bash
ping -c 3 10.0.0.2   # publisher
ping -c 3 10.0.0.3   # BITW
ping -c 3 10.0.1.4   # subscriber
```

## 10. Install Python tools on attacker VM

The attacker VM runs the GOOSE attack and sniffing scripts.

1. Install base Python packages and capture tools:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip tcpdump tshark
```

2. Create a virtual environment:

```bash
python3 -m venv ~/PY_GOOSE
source ~/PY_GOOSE/bin/activate
pip install --upgrade pip
```

3. Install Python packages:

```bash
pip install scapy pyshark colorama
```

4. Grant raw socket capabilities to the virtual environment Python:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f ~/PY_GOOSE/bin/python3)"
getcap "$(readlink -f ~/PY_GOOSE/bin/python3)"
```

You should see something like:

```text
/.../python3 cap_net_admin,cap_net_raw=eip
```

The attacker VM is now ready to run the attack scripts in the `Attacker Test Scripts` directory of this repository.

## 11. Install libIEC61850 on LattePandas

All three LattePandas use libIEC61850 for GOOSE support.

On each LattePanda:

```bash
cd ~
git clone https://github.com/mz-automation/libiec61850.git
cd libiec61850
mkdir build
cd build
cmake ..
make -j"$(nproc)"
sudo make install
sudo ldconfig
```

You can verify the installation with:

```bash
pkg-config --cflags --libs libiec61850
```

This should print compiler and linker flags for the library.

## 12. Clone this repository

On each machine that will build or run code from this project
(Publisher, Subscriber, BITW, attacker VM):

1. Choose a directory, for example `~/projects`.
2. Clone the repository:

```bash
cd ~
mkdir -p projects
cd projects
git clone https://github.com/YOUR_GITHUB_USERNAME/Comodity-SBC-GOOSE-Security-Testbed.git
cd Comodity-SBC-GOOSE-Security-Testbed
```

Replace `YOUR_GITHUB_USERNAME` with your actual GitHub account name.

## 13. Build the C components with make

You are now ready to build the project binaries.

### 13.1 Build on Publisher

On the Publisher LattePanda:

```bash
cd ~/projects/Comodity-SBC-GOOSE-Security-Testbed/GOOSE_Publisher
make
```

This builds:

- `publisher_engine`
- `publication_manager`

### 13.2 Build on Subscriber

On the Subscriber LattePanda:

```bash
cd ~/projects/Comodity-SBC-GOOSE-Security-Testbed/GOOSE_Subscriber
make
```

This builds:

- `subscriber_engine`
- `subscription_manager`

### 13.3 Build on BITW node

On the BITW LattePanda:

```bash
cd ~/projects/Comodity-SBC-GOOSE-Security-Testbed/GOOSE_BITW
make
```

This builds:

- `bitw_engine`
- `bitw_manager`

### 13.4 Build the loggers

On the Publisher LattePanda:

```bash
cd ~/projects/Comodity-SBC-GOOSE-Security-Testbed/Logging/Publisher_Logger
make
```

On the Subscriber LattePanda:

```bash
cd ~/projects/Comodity-SBC-GOOSE-Security-Testbed/Logging/Subscriber_Logger
make
```

This builds:

- `publisher_logger` on the publisher
- `subscriber_logger` on the subscriber

At this point the full environment is prepared and all C components
have been built. For instructions on running the publisher, subscriber,
BITW engine, loggers, and attack scripts, see the main `README.md`.
