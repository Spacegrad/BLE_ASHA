import asyncio
from bleak import BleakScanner
from BLEPacketDecoder import BLEPacketDecoder

LATEST = {}  # addr -> (device, advertisement_data)
DECODER = BLEPacketDecoder()
SCAN_SECONDS = 6.0

last_selected_addr = None

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

""" def build_raw_adv(advertisement_data):
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
            us = str(uuid).lower()
            if len(us) == 4:
                u16 = int(us, 16)
            elif us.endswith("00001000800000805f9b34fb"):
                u16 = int(us[4:8], 16)
            else:
                raise ValueError
            payload = bytes(b)
            entry = bytes([len(payload) + 3, 0x16, u16 & 0xFF, (u16 >> 8) & 0xFF]) + payload
            parts += entry
            continue
        except Exception:
            pass

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
    return bytes(parts) """

def build_raw_adv(advertisement_data):
    parts = bytearray()
    
    # 1. Flags (если есть)
    flags = getattr(advertisement_data, "flags", None)
    if flags is not None:
        parts.extend(bytes([0x02, 0x01, flags]))
    
    # 2. Service UUIDs (16-bit)
    service_uuids = getattr(advertisement_data, "service_uuids", []) or []
    for uuid in service_uuids:
        try:
            # Обрабатываем 16-битные UUID
            if uuid.startswith("0000") and uuid.endswith("-0000-1000-8000-00805f9b34fb"):
                uuid_16 = int(uuid[4:8], 16)
                parts.extend(bytes([0x03, 0x02, uuid_16 & 0xFF, (uuid_16 >> 8) & 0xFF]))
        except Exception:
            pass
    
    # 3. Service Data
    service_data = getattr(advertisement_data, "service_data", None) or {}
    for uuid, data in service_data.items():
        try:
            data_bytes = bytes(data)
            # Для 16-битных UUID
            if uuid.startswith("0000") and uuid.endswith("-0000-1000-8000-00805f9b34fb"):
                uuid_16 = int(uuid[4:8], 16)
                entry_length = len(data_bytes) + 2  # +2 для UUID
                parts.extend(bytes([entry_length + 1, 0x16]))
                parts.extend(bytes([uuid_16 & 0xFF, (uuid_16 >> 8) & 0xFF]))
                parts.extend(data_bytes)
            else:
                # Для других UUID - добавляем как есть
                uuid_bytes = bytes.fromhex(uuid.replace('-', ''))
                entry_length = len(data_bytes) + len(uuid_bytes)
                parts.extend(bytes([entry_length + 1, 0x16]))
                parts.extend(uuid_bytes)
                parts.extend(data_bytes)
        except Exception:
            pass
    
    # 4. Local Name
    name = getattr(advertisement_data, "local_name", None) or getattr(advertisement_data, "local_name_complete", None)
    if name:
        name_bytes = name.encode('utf-8', errors="ignore")
        parts.extend(bytes([len(name_bytes) + 1, 0x09]))
        parts.extend(name_bytes)
    
    # 5. Manufacturer Data
    manufacturer_data = getattr(advertisement_data, "manufacturer_data", None) or {}
    for company_id, data in manufacturer_data.items():
        data_bytes = bytes(data)
        # Company ID в little-endian
        company_id_le = bytes([company_id & 0xFF, (company_id >> 8) & 0xFF])
        entry_length = len(data_bytes) + 2  # +2 для Company ID
        parts.extend(bytes([entry_length + 1, 0xFF]))
        parts.extend(company_id_le)
        parts.extend(data_bytes)
    
    # 6. TX Power (если есть)
    tx_power = getattr(advertisement_data, "tx_power", None)
    if tx_power is not None:
        # Преобразуем в signed byte
        tx_byte = tx_power & 0xFF if tx_power >= 0 else (256 + tx_power) & 0xFF
        parts.extend(bytes([0x02, 0x0A, tx_byte]))
    
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
            print(f"{i:<2} {short_name(device):<18} {addr}")
    last_selected_addr = None
    print_list()
    while True:
        s = input("Enter device number to show adv (L=list & rescan, p=print parsed, q=quit): ").strip()
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
        if s.lower() == "p":
            if last_selected_addr is None:
                print("No device selected yet. Choose a device number first.")
                continue
            entry = LATEST.get(last_selected_addr)
            if not entry:
                print("Previously selected device is no longer available. Rescan (L) to refresh.")
                continue
            device, adv = entry
            if device is None:
                print("Previously selected device is no longer available. Rescan (L) to refresh.")
                continue
            # DECODER expects hex string of raw TLV; build raw bytes from advertisement_data as before
            raw = build_raw_adv(adv)
            if not raw:
                print("No raw advertisement available to parse.")
                continue
            DECODER.decode_and_print(raw.hex())
            continue
        try:
            n = int(s)
        except ValueError:
            print("Enter a number, 'L' to rescan and list, 'p' to print parsed, or 'q' to quit.")
            continue
        current_addrs = addrs()
        if not (1 <= n <= len(current_addrs)):
            print("Invalid number.")
            continue
        # validate n...
        addr = current_addrs[n - 1]
        device, adv = LATEST[addr]
        last_selected_addr = addr
        print_adv_details(device, adv)
        # после показа пакета не печатаем список снова — ждем очередного ввода

if __name__ == "__main__":
    asyncio.run(main_loop())



""" Launch: The script first scans for 5 seconds and prints a list. Input:

- number — show the packet for the selected device (after displaying, it will return to the prompt),
- l — scan again and print the list of found devices,
- p - parse current ADV pack
- q — exit. """