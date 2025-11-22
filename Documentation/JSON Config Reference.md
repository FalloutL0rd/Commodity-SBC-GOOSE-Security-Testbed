# JSON Configuration Reference

This document explains the JSON configuration files used in the Commodity SBC GOOSE Security Testbed so that you can create your own publications, subscriptions, BITW policies, trip logic, and HMAC settings.

Covered files:

- GOOSE publisher publication config: GOOSE_Publisher/publications/healthA.json
- GOOSE subscriber subscription config: GOOSE_Subscriber/subscriptions/healthA_sub.json
- GOOSE subscriber trip logic config: GOOSE_Subscriber/trip_logic/healthA_trip.json
- BITW policy config: GOOSE_BITW/policies/IEDA_healthA.json
- Publisher HMAC config: GOOSE_Publisher/security/hmac.json

The various registry.json files are runtime registries maintained by the manager programs and are not documented here.

## 1. Publisher GOOSE publication config (healthA.json)

Path:

- GOOSE_Publisher/publications/healthA.json

This file defines one GOOSE stream that the publisher can send. The healthA.json file is the reference stream used throughout the testbed.

Typical fields:

```json
{
  "appId": 1000,

  "gocbRef": "IEDA/LLN0$GO$healthA",
  "datSet": "IEDA/LLN0$AnalogValues",
  "goID": "IEDA/LLN0$GO$healthA",

  "dstMac": "01:0c:cd:01:00:01",
  "vlanId": 0,
  "vlanPriority": 0,

  "timeAllowedToLive": 2000,
  "confRev": 1,
  "ndsCom": false,
  "test": false,

  "heartbeat_ms": 1000,

  "dataset": [
    { "name": "deviceUp", "type": "boolean", "value": true, "quality": "good" },
    { "name": "temp",     "type": "integer", "value": 25,   "quality": "good" }
  ]
}
```

Field meanings:

- appId  
  The 16 bit GOOSE AppID. This must match the subscriber and BITW policy for the same stream.

- gocbRef  
  GOOSE control block reference string. Identifies the control block in the IED model. Must match subscriber and BITW for this stream.

- datSet  
  Name of the MMS dataset used by this GOOSE control block.

- goID  
  GOOSE ID string. Often the same as gocbRef in this testbed. Must match the BITW policy stream match.

- dstMac  
  Destination MAC address for the GOOSE frames. Typically a multicast address such as 01:0c:cd:01:00:01.

- vlanId, vlanPriority  
  VLAN tag settings. If vlanId is 0, no VLAN tag is used. If nonzero, the publisher sends VLAN tagged GOOSE frames.

- timeAllowedToLive  
  GOOSE Time Allowed To Live in milliseconds. Used by subscriber and BITW to reason about freshness and offline status.

- confRev  
  Configuration revision integer. Increment this when you change the dataset or other critical properties.

- ndsCom  
  Needs commissioning flag. Usually false in this testbed.

- test  
  GOOSE test flag. Usually false in this testbed.

- heartbeat_ms  
  Heartbeat interval in milliseconds. Publisher sends periodic GOOSE frames at this interval when data does not change.

- dataset  
  Array of dataset entries. Each entry has:
  - name: label for the dataset element, such as "deviceUp" or "temp".
  - type: logical type, "boolean" or "integer" in the current code.
  - value: default or initial value.
  - quality: string such as "good".

The publisher uses this JSON to construct the MMS dataset and the canonical dataset bytes that are included in HMAC coverage when HMAC is enabled.

Creating your own publication JSON:

1. Choose a unique appId.
2. Set gocbRef, datSet, and goID to match your IED naming.
3. Set dstMac to the multicast address you want to use.
4. Decide VLAN usage via vlanId and vlanPriority.
5. Set timeAllowedToLive, confRev, ndsCom, test, and heartbeat_ms.
6. Define the dataset array, using boolean and integer types as needed.
7. Add the new file to the publisher registry so the manager CLI can present it.

## 2. Subscriber GOOSE subscription config (healthA_sub.json)

Path:

- GOOSE_Subscriber/subscriptions/healthA_sub.json

This file tells the subscriber which GOOSE stream to listen for and which trip logic file to use for it.

Typical structure:

```json
{
  "name": "healthA_sub",
  "appId": 1000,
  "gocbRef": "IEDA/LLN0$GO$healthA",
  "dstMac": "01:0c:cd:01:00:01",

  "data_values_count": 2,
  "trip_logic": "trip_logic/healthA_trip.json"
}
```

Field meanings:

- name  
  Friendly name for the subscription. Used by the subscription_manager program when listing available subscriptions.

- appId  
  GOOSE AppID this subscriber should accept. Must match the publisher appId.

- gocbRef  
  GOOSE control block reference. Must match the publisher gocbRef.

- dstMac  
  Destination MAC address to listen for. Should match the publisher dstMac.

- data_values_count  
  Expected number of dataset entries. For healthA, there are two elements: deviceUp and temp.

- trip_logic  
  Path to the trip logic JSON for this subscription. The subscriber uses that file to decide when to trip.

Creating your own subscription JSON:

1. Set name to something descriptive.
2. Set appId and gocbRef to match the publisher configuration.
3. Set dstMac to the same multicast MAC as the publisher.
4. Set data_values_count to the length of the publisher dataset.
5. Set trip_logic to a new trip logic file you create for this stream.

## 3. Subscriber trip logic config (healthA_trip.json)

Path:

- GOOSE_Subscriber/trip_logic/healthA_trip.json

This file defines how the subscriber decides when to trip based on received GOOSE values and timing behavior.

Example structure (shortened):

```json
{
  "name": "healthA_trip",
  "description": "Health testing logic. Trip when health boolean goes false and latched until manager reset.",

  "logic": "all",
  "latch": true,
  "manual_reset_required": true,

  "require_stnum_change": true,
  "require_burst": true,
  "burst_window_ms": 60,
  "burst_min_frames": 3,
  "burst_interval_max_ms": 10,

  "reset_on_stnum_change": false,
  "baseline_relearn_ms": 3000,

  "rules": [
    { "index": 0, "type": "bool", "equals": false, "label": "HealthStatus" }
  ],

  "offline_policy": {
    "timeout_ms": 2000,
    "mark_offline_on_invalid_goose": true
  },

  "reset_policy": {
    "type": "manual_only",
    "normal_required": true,
    "normal_rules": [
      { "index": 0, "type": "bool", "equals": true }
    ],
    "min_sq_in_state": 3,
    "normal_dwell_ms": 2000,
    "no_burst_ms": 500
  },

  "pin_source": false,
  "source_cooldown_ms": 6000
}
```

Key fields:

- name, description  
  Human readable identifiers for the trip logic.

- logic  
  How the rules array is combined:
  - "any": trip if any rule matches.
  - "all": trip only if all rules match.

- latch  
  Indicates that trips are latched once triggered. The implementation already uses a latched state that requires manual reset.

- manual_reset_required  
  Documents that manual reset (signal from the manager) is required to clear a trip.

Gating fields based on stNum and burst behavior:

- require_stnum_change  
  Only allow tripping when a change in stNum is observed, so that the FSM reacts to a new GOOSE state instead of repeated heartbeats.

- require_burst  
  Require a burst of frames after a stNum change before allowing a trip.

- burst_window_ms  
  Length of time window after the stNum change in which the burst is evaluated.

- burst_min_frames  
  Minimum number of frames inside the burst window to consider the change valid.

- burst_interval_max_ms  
  Maximum allowable gap in milliseconds between frames in the burst.

- reset_on_stnum_change  
  Controls whether a new stNum can participate in reset behavior. In healthA it is false.

- baseline_relearn_ms  
  Idle time after which baseline behavior is considered forgotten and the FSM returns to an idle baseline.

Rules array:

Each rule entry refers to a dataset index and a value condition.

Example rule:

```json
{ "index": 0, "type": "bool", "equals": false, "label": "HealthStatus" }
```

Fields:

- index  
  Zero based index into the MMS dataset. For healthA, index 0 is deviceUp.

- type  
  Type of the value, usually "bool" or "int" for this testbed.

- equals  
  Target value. For type "bool", this is true or false; for type "int", a numeric value.

- label  
  Text label used in logging and status output to show which condition was triggered.

Offline policy:

- offline_policy.timeout_ms  
  Maximum time without valid GOOSE updates before considering the stream offline.

- offline_policy.mark_offline_on_invalid_goose  
  Indicates that invalid GOOSE frames contribute to offline state.

Reset policy:

- reset_policy.type  
  Reset semantics. In healthA it is "manual_only".

- reset_policy.normal_required  
  If true, some normal condition must be observed before a reset is considered valid.

- reset_policy.normal_rules  
  Conditions that define a normal state, using the same rule structure as rules.

- reset_policy.min_sq_in_state  
  Minimum number of sequence numbers in the normal state.

- reset_policy.normal_dwell_ms  
  Minimum dwell time in normal state before reset.

- reset_policy.no_burst_ms  
  Minimum time with no burst activity before reset is treated as stable.

Other fields:

- pin_source  
  Reserved for source pinning behavior. Not heavily used in the current testbed.

- source_cooldown_ms  
  Reserved for future timing behavior when switching sources.

Creating your own trip logic JSON:

1. Set name and description.
2. Choose logic ("any" or "all").
3. Decide whether to require stNum changes and bursts to gate trips.
4. Define rules that map dataset indices to boolean or integer conditions.
5. Optionally set offline_policy and reset_policy to describe normal and offline behavior.
6. Reference this file in the subscriber subscription JSON.

## 4. BITW policy config (IEDA_healthA.json)

Path:

- GOOSE_BITW/policies/IEDA_healthA.json

This file tells the BITW engine which streams to protect, how to derive HMAC keys, and what freshness limits to enforce.

Example structure (simplified):

```json
{
  "mode": "monitor",
  "stripTag": false,
  "timeAllowedToLive_ms": 2000,
  "window": { "maxSqGap": 8, "maxAge_ms": 5000 },

  "devices": [{
    "deviceId": "IEDA",
    "k_device_hex": "b29a1e653ce6387f189387867cf43201f78032e60ae1d75e00587f8534b74317",
    "kdfInfoFmt": "GOOSE|{goID}|{gocbRef}|{appId}",
    "streams": [{
      "name": "healthA",
      "allowUnsigned": true,
      "match": {
        "appId": 1000,
        "goID":   "IEDA/LLN0$GO$healthA",
        "gocbRef":"IEDA/LLN0$GO$healthA"
      }
    }]
  }]
}
```

Top level behavior:

- mode  
  BITW run mode:
  - "monitor": check HMAC and freshness but do not drop frames.
  - "enforce": drop frames that fail HMAC or freshness checks.

- stripTag  
  If true, BITW removes the HMAC tag from the dataset before forwarding frames. In this testbed it is usually false.

- timeAllowedToLive_ms  
  Time Allowed To Live in milliseconds from the BITW perspective.

- window  
  Freshness and sequence window:
  - maxSqGap: maximum allowed gap in sqNum before frames are considered too far apart.
  - maxAge_ms: maximum age of frames before they are considered stale.

Devices and keys:

- devices  
  Array of devices, each representing a logical IED or group of streams that share a device key.

- deviceId  
  Identifier for the device.

- k_device_hex  
  Hex encoded device key. Must match the publisher HMAC config key_device_hex.

- kdfInfoFmt  
  HKDF info format string. Must match the publisher HMAC config infoFmt. Placeholders such as {goID}, {gocbRef}, and {appId} are filled in for each stream.

Streams:

Each device has a streams array. For each stream:

- name  
  Friendly name for the stream.

- allowUnsigned  
  If true, unsigned GOOSE frames (no tag) are allowed. If false, they are treated as invalid.

- match  
  Matching parameters that select this stream:
  - appId: must match the GOOSE frame appId.
  - goID: must match the GOOSE ID.
  - gocbRef: must match the control block reference.

Creating your own BITW policy JSON:

1. Set mode to "monitor" while testing, then switch to "enforce" when ready.
2. Decide whether stripTag should be true or false.
3. Set timeAllowedToLive_ms and window fields to match your environment.
4. Under devices:
   - Add a device entry with deviceId.
   - Set k_device_hex to match the publisher HMAC key_device_hex.
   - Set kdfInfoFmt to match publisher HMAC kdf.infoFmt.
5. Under streams:
   - Add stream entries that match new publications by appId, goID, and gocbRef.
   - Decide whether each stream allows unsigned frames.

## 5. Publisher HMAC config (hmac.json)

Path:

- GOOSE_Publisher/security/hmac.json

This file controls whether the publisher signs GOOSE frames with HMAC and how it derives keys.

Example:

```json
{
  "enabled": false,
  "mode": "hmac-sha256-16",
  "key_device_hex": "b29a1e653ce6387f189387867cf43201f78032e60ae1d75e00587f8534b74317",
  "kdf": { "algo": "HKDF-SHA256", "infoFmt": "GOOSE|{goID}|{gocbRef}|{appId}" },
  "coverage": ["gocbRef","goID","appId","stNum","sqNum","dataset"],
  "tagPlacement": "dataset:last",
  "truncate_bytes": 16
}
```

Field meanings:

- enabled  
  If true, publisher signs GOOSE frames with HMAC and appends a tag to the dataset. If false, frames are unsigned.

- mode  
  Descriptive label for the HMAC mode. Here, HMAC SHA 256 truncated to 16 bytes.

- key_device_hex  
  Hex encoded device key used as the HKDF input key. Must match k_device_hex in the BITW policy.

- kdf  
  HKDF configuration:
  - algo: algorithm used for key derivation, typically "HKDF-SHA256".
  - infoFmt: format string for the HKDF info field. The placeholders {goID}, {gocbRef}, and {appId} are replaced with values for each stream.

- coverage  
  List of logical fields included in the canonical HMAC input. In this testbed, coverage is:
  - gocbRef
  - goID
  - appId
  - stNum
  - sqNum
  - dataset

- tagPlacement  
  Where to put the HMAC tag. "dataset:last" means the tag is encoded as the last element of the dataset.

- truncate_bytes  
  Number of bytes of the 32 byte HMAC output that are sent in the frame. 16 bytes in this example.

Creating your own HMAC config:

1. Set enabled to true to turn on HMAC.
2. Generate a random 32 byte value and encode it as hex for key_device_hex.
3. Keep kdf.algo consistent between publisher and BITW.
4. Keep kdf.infoFmt in sync with the BITW kdfInfoFmt format.
5. Leave coverage and tagPlacement unchanged unless you also change the BITW implementation.
6. Choose truncate_bytes (16 is a common choice).

## 6. Summary

To define a new complete GOOSE stream:

1. Create a new publication JSON in GOOSE_Publisher/publications with:
   - New appId, gocbRef, goID, dstMac, and dataset.
2. Create a matching subscription JSON in GOOSE_Subscriber/subscriptions with:
   - Same appId, gocbRef, dstMac, and data_values_count.
3. Create a trip logic JSON in GOOSE_Subscriber/trip_logic that:
   - References dataset indices and conditions that should cause a trip.
4. Update or create a BITW policy JSON in GOOSE_BITW/policies that:
   - Uses the same key_device_hex as the publisher HMAC config.
   - Matches the new stream by appId, goID, and gocbRef.
5. Ensure the publisher HMAC config and BITW policy have matching key and KDF settings if HMAC is enabled.

These JSON files are the main way to customize behavior in the testbed without changing any C or Python code.
