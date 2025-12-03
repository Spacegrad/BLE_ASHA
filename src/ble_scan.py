import asyncio
from bleak import BleakScanner, BleakClient
from bleak.exc import BleakError
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

# Краткие имена для стандартных сервисов и характеристик
STANDARD_SERVICES = {
    "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
    "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "00001812-0000-1000-8000-00805f9b34fb": "Human Interface Device",
    "0000fd0f-0000-1000-8000-00805f9b34fb": "ASHA Service",
}

STANDARD_CHARACTERISTICS = {
    "00002a00-0000-1000-8000-00805f9b34fb": "Device Name",
    "00002a01-0000-1000-8000-00805f9b34fb": "Appearance",
    "00002a04-0000-1000-8000-00805f9b34fb": "Peripheral Preferred Connection Parameters",
    "00002a05-0000-1000-8000-00805f9b34fb": "Service Changed",
    "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
    "00002a24-0000-1000-8000-00805f9b34fb": "Model Number String",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number String",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Revision String",
    "00002a27-0000-1000-8000-00805f9b34fb": "Hardware Revision String",
    "00002a28-0000-1000-8000-00805f9b34fb": "Software Revision String",
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer Name String",
    "00002a2a-0000-1000-8000-00805f9b34fb": "IEEE 11073-20601 Regulatory Certification Data List",
    "00002a50-0000-1000-8000-00805f9b34fb": "PnP ID",
}

def get_service_name(uuid: str) -> str:
    """Возвращает читаемое имя сервиса по UUID"""
    uuid_lower = uuid.lower()
    if uuid_lower in STANDARD_SERVICES:
        return STANDARD_SERVICES[uuid_lower]
    return uuid

def get_characteristic_name(uuid: str) -> str:
    """Возвращает читаемое имя характеристики по UUID"""
    uuid_lower = uuid.lower()
    if uuid_lower in STANDARD_CHARACTERISTICS:
        return STANDARD_CHARACTERISTICS[uuid_lower]
    return uuid

def format_properties(properties):
    """Форматирует свойства характеристики в читаемый вид"""
    props_list = []
    if "read" in properties:
        props_list.append("Read")
    if "write" in properties:
        props_list.append("Write")
    if "write-without-response" in properties:
        props_list.append("WriteWoResp")
    if "notify" in properties:
        props_list.append("Notify")
    if "indicate" in properties:
        props_list.append("Indicate")
    if "broadcast" in properties:
        props_list.append("Broadcast")
    return "[" + ", ".join(props_list) + "]"

def decode_characteristic_value(value: bytes) -> str:
    """Декодирует значение характеристики в читаемый формат"""
    if not value:
        return "<empty>"
    
    # Пытаемся декодировать как строку
    try:
        text = value.decode('utf-8', errors='ignore').strip()
        if text and all(ord(c) < 128 for c in text[:20]):  # Проверяем на ASCII
            return f'"{text[:50]}"' + ("..." if len(text) > 50 else "")
    except:
        pass
    
    # Если не строка, показываем hex
    hex_str = value.hex().upper()
    if len(hex_str) > 20:
        return f"0x{hex_str[:20]}..."
    return f"0x{hex_str}"

async def explore_device(device_address: str, device_name: str = None):
    """
    Подключается к устройству и отображает все сервисы и характеристики
    """
    print(f"\n{'='*60}")
    print(f"Connecting to device: {device_name or device_address}")
    print(f"Address: {device_address}")
    print(f"{'='*60}\n")
    
    client = None
    try:
        # Подключаемся с таймаутом 7 секунд
        client = BleakClient(device_address, timeout=7.0)
        
        print("Attempting connection...")
        await client.connect()
        
        if client.is_connected:
            print("✓ Connected successfully!\n")
            print("Discovering services and characteristics...")
            
            # Для некоторых версий bleak нужно явно вызвать discover()
            try:
                await client.discover()
            except AttributeError:
                pass  # В некоторых версиях это делается автоматически
            
            # Получаем все сервисы и характеристики
            # Способ получения зависит от версии bleak
            services = []
            try:
                # Способ 1: через свойство services
                services = client.services
            except AttributeError:
                try:
                    # Способ 2: через get_services() для старых версий
                    services = await client.get_services()
                except AttributeError:
                    # Способ 3: напрямую через _services
                    services = getattr(client, '_services', [])
            
            if isinstance(services, list):
                services_list = services
            else:
                # Если это не список, пытаемся преобразовать
                services_list = list(services) if hasattr(services, '__iter__') else []
            
            print(f"Found {len(services_list)} service(s)\n")
            
            # Отображаем в виде дерева
            service_count = 0
            for service in services_list:
                service_count += 1
                
                # Получаем характеристики
                try:
                    characteristics = service.characteristics
                except AttributeError:
                    characteristics = []
                
                # Имя сервиса
                service_name = get_service_name(service.uuid)
                handle = service.handle if hasattr(service, 'handle') else "N/A"
                
                # UUID в коротком формате если возможно
                uuid_display = service.uuid
                if uuid_display.startswith("0000") and uuid_display.endswith("-0000-1000-8000-00805f9b34fb"):
                    uuid_short = uuid_display[4:8].upper()
                    uuid_display = f"0x{uuid_short}"
                
                print(f"[{service_count}] Service: {service_name}")
                print(f"    UUID: {uuid_display}")
                print(f"    Handle: 0x{handle:04X}" if isinstance(handle, int) else f"    Handle: {handle}")
                
                # Характеристики этого сервиса
                char_count = 0
                for char in characteristics:
                    char_count += 1
                    
                    # Имя характеристики
                    char_name = get_characteristic_name(char.uuid)
                    
                    # UUID в коротком формате если возможно
                    char_uuid_display = char.uuid
                    if char_uuid_display.startswith("0000") and char_uuid_display.endswith("-0000-1000-8000-00805f9b34fb"):
                        char_uuid_short = char_uuid_display[4:8].upper()
                        char_uuid_display = f"0x{char_uuid_short}"
                    
                    # Свойства
                    properties = []
                    try:
                        if hasattr(char, 'properties'):
                            props = char.properties
                            if isinstance(props, list):
                                properties = props
                            else:
                                # Преобразуем объект Properties в список
                                properties = [p for p in ['read', 'write', 'write-without-response', 'notify', 'indicate', 'broadcast'] 
                                            if getattr(props, p, False)]
                    except:
                        properties = []
                    
                    properties_str = "[" + ", ".join([p.capitalize() for p in properties]) + "]"
                    
                    # Handle
                    char_handle = char.handle if hasattr(char, 'handle') else "N/A"
                    
                    # Дескрипторы
                    try:
                        descriptors = char.descriptors if hasattr(char, 'descriptors') else []
                        desc_count = len(descriptors) if descriptors else 0
                    except:
                        desc_count = 0
                    
                    desc_handle = f", Descriptors: {desc_count}" if desc_count > 0 else ""
                    
                    # Определяем префикс для дерева
                    prefix = "    └── " if char_count == len(characteristics) else "    ├── "
                    
                    print(f"{prefix}[{char_count}] Characteristic: {char_name}")
                    print(f"        UUID: {char_uuid_display}")
                    print(f"        Handle: 0x{char_handle:04X}" if isinstance(char_handle, int) else f"        Handle: {char_handle}")
                    print(f"        Properties: {properties_str}{desc_handle}")
                    
                    # Читаем значение если характеристика readable
                    if "read" in properties:
                        try:
                            # Добавляем таймаут для чтения
                            value = await asyncio.wait_for(client.read_gatt_char(char.uuid), timeout=3.0)
                            decoded_value = decode_characteristic_value(value)
                            print(f"        Value: {decoded_value}")
                        except asyncio.TimeoutError:
                            print(f"        Value: <read timeout>")
                        except Exception as e:
                            print(f"        Value: <read error: {str(e)}>")
                
                if not characteristics:
                    print("    └── No characteristics found")
                
                print()  # Пустая строка между сервисами
            
            print(f"\nTotal: {len(services_list)} service(s)")
            total_chars = sum(len(getattr(s, 'characteristics', [])) for s in services_list)
            print(f"Total characteristics: {total_chars}")
            
        else:
            print("✗ Connection failed: Not connected after connect() call")
            
    except asyncio.TimeoutError:
        print("✗ Connection timeout: Device did not respond within 7 seconds")
    except BleakError as e:
        print(f"✗ Bleak error: {str(e)}")
    except Exception as e:
        print(f"✗ Unexpected error: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()  # Для отладки
    finally:
        # Всегда пытаемся отключиться
        if client and client.is_connected:
            try:
                print("\nDisconnecting...")
                await client.disconnect()
                print("✓ Disconnected successfully")
            except Exception as e:
                print(f"⚠ Warning during disconnect: {str(e)}")
    
    print(f"\n{'='*60}")

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
        print(f"\n{'='*50}")
        print(f"Found {len(addrs())} device(s):")
        print(f"{'='*50}")
        for i, addr in enumerate(addrs(), start=1):
            device, _ = LATEST[addr]
            print(f"{i:<2} {short_name(device):<25} {addr}")
        print(f"{'='*50}")
    
    last_selected_addr = None
    print_list()
    
    while True:
        s = input("\nEnter device number to show adv (L=list & rescan, p=print parsed, c=connect & explore, q=quit): ").strip()
        if not s:
            continue
        if s.lower() == "q":
            print("Goodbye!")
            break
        if s.lower() == "l":
            print(f"\nRescanning for {SCAN_SECONDS} seconds...")
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
            raw = build_raw_adv(adv)
            if not raw:
                print("No raw advertisement available to parse.")
                continue
            DECODER.decode_and_print(raw.hex())
            continue
        if s.lower() == "c":
            if last_selected_addr is None:
                print("No device selected yet. Choose a device number first.")
                continue
            entry = LATEST.get(last_selected_addr)
            if not entry:
                print("Selected device is no longer available. Rescan (L) to refresh.")
                continue
            device, adv = entry
            await explore_device(device.address, short_name(device))
            continue
        
        try:
            n = int(s)
        except ValueError:
            print("Enter a number, 'L' to rescan and list, 'p' to print parsed, 'c' to connect & explore, or 'q' to quit.")
            continue
        
        current_addrs = addrs()
        if not (1 <= n <= len(current_addrs)):
            print("Invalid number.")
            continue
        
        addr = current_addrs[n - 1]
        device, adv = LATEST[addr]
        last_selected_addr = addr
        print_adv_details(device, adv)

if __name__ == "__main__":
    asyncio.run(main_loop())