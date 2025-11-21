import asyncio
from bleak import BleakScanner

LATEST = {}  # addr -> (device, advertisement_data)
SCAN_SECONDS = 5.0

def detection_callback(device, advertisement_data):
    LATEST[getattr(device, "address", "<no-address>")] = (device, advertisement_data)

async def scan_for(seconds=SCAN_SECONDS):
    LATEST.clear()
    scanner = BleakScanner(detection_callback=detection_callback)
    await scanner.start()
    await asyncio.sleep(seconds)
    await scanner.stop()

def short_name(device):
    return getattr(device, "name", None) or "<no-name>"

def format_tlv_hex(ad_bytes: bytes) -> str:
    return " ".join(f"{b:02x}" for b in ad_bytes)

def build_raw_adv(advertisement_data):
    raw = getattr(advertisement_data, "raw_data", None)
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    parts = bytearray()
    flags = getattr(advertisement_data, "flags", None)
    if flags is not None:
        parts += bytes([2, 0x01, flags])
    sd = getattr(advertisement_data, "service_data", None) or {}
    for uuid, b in sd.items():
        try:
            if isinstance(uuid, str) and uuid.lower().endswith("00001000800000805f9b34fb"):
                u16 = int(uuid[4:8], 16)
                payload = bytes(b)
                entry = bytes([len(payload) + 3, 0x16, u16 & 0xFF, (u16 >> 8) & 0xFF]) + payload
                parts += entry
                continue
        except Exception:
            pass
    name = getattr(advertisement_data, "local_name", None) or getattr(advertisement_data, "local_name_complete", None)
    if name:
        nb = name.encode(errors="ignore")
        parts += bytes([len(nb) + 1, 0x09]) + nb
    md = getattr(advertisement_data, "manufacturer_data", None) or {}
    for cid, payload in md.items():
        payload_b = bytes(payload)
        cid_le = bytes([cid & 0xFF, (cid >> 8) & 0xFF])
        entry = bytes([len(payload_b) + len(cid_le) + 1, 0xFF]) + cid_le + payload_b
        parts += entry
    return bytes(parts)

def print_adv_details(device, advertisement_data):
    addr = getattr(device, "address", "<no-address>")
    name = short_name(device)
    rssi = getattr(advertisement_data, "rssi", None)
    print(f"{name}, {addr}  RSSI={rssi}")
    md = getattr(advertisement_data, "manufacturer_data", None) or {}
    if md:
        print("  Manufacturer data:")
        for cid, b in md.items():
            print(f"    0x{cid:04X}: {bytes(b).hex()}")
    sd = getattr(advertisement_data, "service_data", None) or {}
    if sd:
        print("  Service data:")
        for uuid, b in sd.items():
            print(f"    {uuid}: {bytes(b).hex()}")
    su = getattr(advertisement_data, "service_uuids", None) or []
    if su:
        print("  Service UUIDs:", ", ".join(su))
    tx = getattr(advertisement_data, "tx_power", None)
    if tx is not None:
        print(f"  TX Power: {tx}")
    raw = build_raw_adv(advertisement_data)
    if raw:
        print("  Raw TLV hex:", format_tlv_hex(raw))
    print()

async def main_loop():
    print(f"Scanning the BLE. Please wait {SCAN_SECONDS} seconds.")
    await scan_for(SCAN_SECONDS)
    addrs = lambda: list(LATEST.keys())

    def print_list():
        for i, addr in enumerate(addrs(), start=1):
            device, _ = LATEST[addr]
            print(f"{i}. {short_name(device)}, {addr}")

    print_list()
    while True:
        s = input("Enter device number to show adv (L=list & rescan, q=quit): ").strip()
        if not s:
            continue
        if s.lower() == "q":
            break
        if s.lower() == "l":
            print(f"Rescanning for {SCAN_SECONDS} seconds...")
            await scan_for(SCAN_SECONDS)
            if not LATEST:
                print("No devices found.")
            print_list()
            continue
        try:
            n = int(s)
        except ValueError:
            print("Enter a number, 'L' to rescan and list, or 'q' to quit.")
            continue
        current_addrs = addrs()
        if not (1 <= n <= len(current_addrs)):
            print("Invalid number.")
            continue
        addr = current_addrs[n - 1]
        device, adv = LATEST[addr]
        print_adv_details(device, adv)
        # после показа пакета не печатаем список снова — ждем очередного ввода

if __name__ == "__main__":
    asyncio.run(main_loop())



""" A compact working Python script for Bleak 1.1.1 (Windows) that:

- scans for 5 seconds,
- outputs a numbered list of devices: "N. Name, MAC" (name or ),
- requests the device number and displays its last received advertising packet (manufacturer/service data, service UUIDs, raw TLV hex),
- then waits for the number to be entered again (enter q to quit). """