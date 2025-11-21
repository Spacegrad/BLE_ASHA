import asyncio
from bleak import BleakScanner

# global storage: addr -> (device, advertisement_data)
LATEST = {}

def detection_callback(device, advertisement_data):
    addr = getattr(device, "address", "<no-address>")
    # сохраняем последнюю пару
    LATEST[addr] = (device, advertisement_data)

async def scan_for(seconds=5.0):
    scanner = BleakScanner(detection_callback=detection_callback)
    await scanner.start()
    await asyncio.sleep(seconds)
    await scanner.stop()

def short_name(device):
    return getattr(device, "name", None) or "<no-name>"

def format_tlv_hex(ad_bytes: bytes) -> str:
    # представление рекламного пакета как последовательность байт в hex с пробелами
    return " ".join(f"{b:02x}" for b in ad_bytes)

def build_raw_adv(advertisement_data):
    # Попытка получить "сырые" рекламные байты: на WinRT AdvertisementData имеет поле raw_data (platform dependent)
    # Если нет — составим TLV из известных полей (service_data, manufacturer_data, name, flags) — близкая реконструкция.
    raw = getattr(advertisement_data, "raw_data", None)
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    # fallback: reconstruct minimal TLV using available fields
    parts = bytearray()
    # flags
    flags = getattr(advertisement_data, "flags", None)
    if flags is not None:
        parts += bytes([2, 0x01, flags])
    # service_data (16-bit) -> Type 0x16
    sd = getattr(advertisement_data, "service_data", None) or {}
    for uuid, b in sd.items():
        # try to extract 16-bit uuid if possible (xxxxxxxx-0000-1000-8000-00805f9b34fb)
        try:
            if isinstance(uuid, str) and uuid.lower().endswith("00001000800000805f9b34fb"):
                u16 = int(uuid[4:8], 16)
                payload = bytes(b)
                entry = bytes([len(payload) + 3, 0x16, u16 & 0xFF, (u16 >> 8) & 0xFF]) + payload
                parts += entry
                continue
        except Exception:
            pass
        # generic service data as 0x16 with uuid bytes unknown: skip reconstruct
    # complete local name
    name = getattr(advertisement_data, "local_name", None) or getattr(advertisement_data, "local_name_complete", None)
    if not name:
        # bleak uses service_uuids and may provide name via device; skip if not present
        name = None
    if name:
        nb = name.encode(errors="ignore")
        parts += bytes([len(nb) + 1, 0x09]) + nb
    # manufacturer data 0xFF (company id LE + payload)
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
    # manufacturer_data
    md = getattr(advertisement_data, "manufacturer_data", None) or {}
    if md:
        print("  Manufacturer data:")
        for cid, b in md.items():
            bb = bytes(b)
            print(f"    0x{cid:04X}: {bb.hex()}")
    # service_data
    sd = getattr(advertisement_data, "service_data", None) or {}
    if sd:
        print("  Service data:")
        for uuid, b in sd.items():
            print(f"    {uuid}: {bytes(b).hex()}")
    # service_uuids
    su = getattr(advertisement_data, "service_uuids", None) or []
    if su:
        print("  Service UUIDs:", ", ".join(su))
    tx = getattr(advertisement_data, "tx_power", None)
    if tx is not None:
        print(f"  TX Power: {tx}")
    # raw TLV bytes (best-effort)
    raw = build_raw_adv(advertisement_data)
    if raw:
        print("  Raw TLV hex:", format_tlv_hex(raw))
    print()

async def main_loop():
    await scan_for(5.0)
    # build index list
    addrs = list(LATEST.keys())
    if not addrs:
        print("No devices found.")
        return
    while True:
        # print numbered list
        for i, addr in enumerate(addrs, start=1):
            device, adv = LATEST[addr]
            print(f"{i}. {short_name(device)}, {addr}")
        s = input("Enter device number to show adv (q to quit): ").strip()
        if s.lower() == "q":
            break
        try:
            n = int(s)
            if not (1 <= n <= len(addrs)):
                print("Invalid number.")
                continue
        except ValueError:
            print("Enter a number or q.")
            continue
        addr = addrs[n - 1]
        device, adv = LATEST[addr]
        print_adv_details(device, adv)
        # loop continues, allow user to pick again

if __name__ == "__main__":
    asyncio.run(main_loop())
