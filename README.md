# Commodity SBC GOOSE Security Testbed

This repository contains an open source IEC 61850 GOOSE security testbed
implemented on commodity single board computers (LattePandas).

The testbed includes:

- A C based GOOSE publisher with optional HMAC authentication.
- A C based GOOSE subscriber with JSON configured trip logic.
- A bump in the wire (BITW) security device that bridges two Ethernet
  interfaces and enforces HMAC and freshness policies on GOOSE traffic.
- Publisher and subscriber side C loggers for GOOSE frames.
- A Python latency analyzer that compares publisher and subscriber logs.
- Preconfigured attacker scripts for sending and sniffing GOOSE traffic.

The reference GOOSE stream used throughout the project is called `healthA`.
It appears in publisher, subscriber, BITW policy, logger samples, and attacker
test scripts so that a single configuration can exercise the entire path.

## Repository layout

Top level directories:

- `GOOSE_Publisher`  
  C GOOSE publisher, configuration, and HMAC settings.

- `GOOSE_Subscriber`  
  C GOOSE subscriber, subscription configuration, and trip logic.

- `GOOSE_BITW`  
  BITW engine and policy definitions.

- `Logging`  
  Publisher and subscriber loggers, latency analyzer, and sample CSVs
  from experiments.

- `Attacker Test Scripts`  
  Python scripts for GOOSE trip, swarm (flood), and sniffing.

- `Documentation`  
  Topology images and reproducibility guide.

- `LICENSE`  
  GPLv3 license for this project.

### GOOSE publisher

`GOOSE_Publisher` contains:

- `src/`  
  Publisher core logic, configuration loader, MMS and GOOSE helpers,
  and authentication code.

- `publications/healthA.json`  
  Reference publication configuration that defines the `healthA` stream
  (AppID, goID, VLAN, and dataset).

- `publications/registry.json`  
  Registry for available publications.

- `security/hmac.json`  
  HMAC key and parameters used by the publisher and BITW.

After building with `make`, this directory contains:

- `publisher_engine`
- `publication_manager`

### GOOSE subscriber

`GOOSE_Subscriber` contains:

- `src/`  
  Subscriber core logic, subscription manager, and configuration loader.

- `subscriptions/healthA_sub.json`  
  Subscription configuration that matches the `healthA` publication.

- `subscriptions/registry.json`  
  Registry for available subscriptions.

- `trip_logic/healthA_trip.json`  
  JSON based trip rules for the `healthA` stream.

After building with `make`, this directory contains:

- `subscriber_engine`
- `subscription_manager`

### BITW engine

`GOOSE_BITW` contains:

- `src/`  
  BITW core engine, policy loader, freshness checks, and GOOSE parser.

- `policies/IEDA_healthA.json`  
  BITW policy that protects the `healthA` stream.

- `policies/registry.json`  
  Registry for available BITW policies.

After building with `make`, this directory contains:

- `bitw_engine`
- `bitw_manager`

### Logging and analysis

`Logging` contains:

- `Publisher_Logger`  
  C logger and Makefile for `publisher_logger`.

- `Subscriber_Logger`  
  C logger and Makefile for `subscriber_logger`.

- `latency_analyzer.py`  
  Reads publisher and subscriber CSV logs, matches frames by `(appId, stNum, sqNum)`,
  and computes latency statistics.

- `Analyzer Log Samples`  
  Sample CSV logs from three scenarios:
  - No BITW
  - BITW + Monitor
  - BITW + Enforce

Each scenario contains five one minute runs of publisher and subscriber logs.

### Attacker test scripts

`Attacker Test Scripts` contains:

- `goose_trip.py`  
  Sends a small sequence of malicious or crafted GOOSE frames that match
  the `healthA` publication.

- `goose_swarm.py`  
  Generates a sustained flood of GOOSE frames on the `healthA` stream
  for denial of service or stress testing.

- `goose_sniff.py`  
  Sniffs GOOSE traffic on the attacker interface and can write packets
  to a pcap file.

These scripts are designed to run from a Linux VM in bridged mode on the
GOOSE LAN, using a virtual environment with Scapy and Pyshark installed.

## Reproducibility and setup

For a complete, step by step setup guide from bare hardware through building
all project binaries, see:

- `Documentation/Reproducibility.md`

That document covers:

- Hardware and cabling
- Ubuntu installation on all LattePandas
- Management network over Wi-Fi
- GOOSE LAN addressing and switch layout
- BITW network configuration (two interface setup)
- Attacker VM configuration in bridged mode
- Base package installation
- libIEC61850 installation
- Cloning this repository
- Running `make` in each component directory

This README focuses on project overview and how to use the built components.

## Quick start (after setup and build)

The following assumes you have followed the reproducibility guide and
successfully built all binaries with `make`.

### 1. Start publisher and subscriber

On the Publisher LattePanda:

```bash
cd GOOSE_Publisher
sudo ./publication_manager
```

Use the interactive menu to start the `healthA` publication, which loads:

- `publications/healthA.json`
- `security/hmac.json`

On the Subscriber LattePanda:

```bash
cd GOOSE_Subscriber
sudo ./subscription_manager
```

Use the menu to start the `healthA` subscription, which loads:

- `subscriptions/healthA_sub.json`
- `trip_logic/healthA_trip.json`

Verify that the subscriber prints valid GOOSE events and applies the trip logic.

### 2. Use BITW

On the BITW LattePanda:

```bash
cd GOOSE_BITW
sudo ./bitw_manager
```

Use the menu to start a BITW engine instance that:

- Uses `policies/IEDA_healthA.json`
- Forwards GOOSE traffic between its two wired interfaces (side A and side B) according to the selected policy

You can configure policies in monitor mode (observe but do not drop) or enforce
mode (drop frames that fail HMAC or freshness checks).

### 3. Run GOOSE loggers

On the Publisher LattePanda:

```bash
cd Logging/Publisher_Logger
sudo ./publisher_logger enp1s0
```

On the Subscriber LattePanda:

```bash
cd Logging/Subscriber_Logger
sudo ./subscriber_logger enp1s0
```

Each logger:

- Daemonizes into the background.
- Waits until the top of the next minute.
- Logs each parsed GOOSE frame as a CSV row:

```text
epoch_us,appId,stNum,sqNum
```

Files are written under each logger directory in the `logs` subdirectory.

### 4. Run attacker scripts

On the attacker VM (Linux, with the `PY_GOOSE` virtual environment):

```bash
cd "Attacker Test Scripts"
source ~/PY_GOOSE/bin/activate
```

Example commands:

```bash
# Trigger a short trip sequence
sudo python3 goose_trip.py -i enp0s3 -t

# Send an infinite topspeed flood (requires tcpreplay):
sudo python3 goose_swarm.py -i eth0 --fast

# Sniff GOOSE traffic for 30 seconds and write to a pcap file
sudo python3 goose_sniff.py -i enp0s3 -s 30 -w goose_attack.pcap
```

Replace `enp0s3` with the correct interface name in your VM/Linux Machine.

### 5. Analyze latency

After running an experiment, copy or reference the matching publisher and
subscriber CSV logs, then run:

```bash
cd Logging
python3 latency_analyzer.py "Analyzer Log Samples/No BITW/pub_logs/publisher_YYYYMMDD_HHMM.csv" "Analyzer Log Samples/No BITW/sub_logs/subscriber_YYYYMMDD_HHMM.csv"
```

Or point the analyzer at your own log files from the `logs` directories.

The script prints average, median, minimum, maximum, and 95th percentile
latency, as well as counts of unmatched or non positive samples.

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0).

The C components link against the libIEC61850 library, which is also released
under GPLv3. By contributing to this repository, you agree that your
contributions will be licensed under the same GPL-3.0 terms.
