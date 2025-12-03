import asyncio
import struct
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
    "00002a02-0000-1000-8000-00805f9b34fb": "Peripheral Privacy Flag",
    "00002a03-0000-1000-8000-00805f9b34fb": "Reconnection Address",
    "00002a04-0000-1000-8000-00805f9b34fb": "Peripheral Preferred Connection Parameters",
    "00002a05-0000-1000-8000-00805f9b34fb": "Service Changed",
    "00002a06-0000-1000-8000-00805f9b34fb": "Alert Level",
    "00002a07-0000-1000-8000-00805f9b34fb": "Tx Power Level",
    "00002a08-0000-1000-8000-00805f9b34fb": "Date Time",
    "00002a09-0000-1000-8000-00805f9b34fb": "Day of Week",
    "00002a0a-0000-1000-8000-00805f9b34fb": "Day Date Time",
    "00002a0c-0000-1000-8000-00805f9b34fb": "Exact Time 256",
    "00002a0d-0000-1000-8000-00805f9b34fb": "DST Offset",
    "00002a0e-0000-1000-8000-00805f9b34fb": "Time Zone",
    "00002a0f-0000-1000-8000-00805f9b34fb": "Local Time Information",
    "00002a11-0000-1000-8000-00805f9b34fb": "Time with DST",
    "00002a12-0000-1000-8000-00805f9b34fb": "Time Accuracy",
    "00002a13-0000-1000-8000-00805f9b34fb": "Time Source",
    "00002a14-0000-1000-8000-00805f9b34fb": "Reference Time Information",
    "00002a16-0000-1000-8000-00805f9b34fb": "Time Update Control Point",
    "00002a17-0000-1000-8000-00805f9b34fb": "Time Update State",
    "00002a18-0000-1000-8000-00805f9b34fb": "Glucose Measurement",
    "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
    "00002a1a-0000-1000-8000-00805f9b34fb": "Battery Power State",
    "00002a1b-0000-1000-8000-00805f9b34fb": "Battery Level State",
    "00002a1c-0000-1000-8000-00805f9b34fb": "Temperature Measurement",
    "00002a1d-0000-1000-8000-00805f9b34fb": "Temperature Type",
    "00002a1e-0000-1000-8000-00805f9b34fb": "Intermediate Temperature",
    "00002a21-0000-1000-8000-00805f9b34fb": "Measurement Interval",
    "00002a22-0000-1000-8000-00805f9b34fb": "Boot Keyboard Input Report",
    "00002a23-0000-1000-8000-00805f9b34fb": "System ID",
    "00002a24-0000-1000-8000-00805f9b34fb": "Model Number String",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number String",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Revision String",
    "00002a27-0000-1000-8000-00805f9b34fb": "Hardware Revision String",
    "00002a28-0000-1000-8000-00805f9b34fb": "Software Revision String",
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer Name String",
    "00002a2a-0000-1000-8000-00805f9b34fb": "IEEE 11073-20601 Regulatory Certification Data List",
    "00002a2b-0000-1000-8000-00805f9b34fb": "Current Time",
    "00002a31-0000-1000-8000-00805f9b34fb": "Scan Refresh",
    "00002a32-0000-1000-8000-00805f9b34fb": "Boot Keyboard Output Report",
    "00002a33-0000-1000-8000-00805f9b34fb": "Boot Mouse Input Report",
    "00002a34-0000-1000-8000-00805f9b34fb": "Glucose Measurement Context",
    "00002a35-0000-1000-8000-00805f9b34fb": "Blood Pressure Measurement",
    "00002a36-0000-1000-8000-00805f9b34fb": "Intermediate Cuff Pressure",
    "00002a37-0000-1000-8000-00805f9b34fb": "Heart Rate Measurement",
    "00002a38-0000-1000-8000-00805f9b34fb": "Body Sensor Location",
    "00002a39-0000-1000-8000-00805f9b34fb": "Heart Rate Control Point",
    "00002a3f-0000-1000-8000-00805f9b34fb": "Alert Status",
    "00002a40-0000-1000-8000-00805f9b34fb": "Ringer Control Point",
    "00002a41-0000-1000-8000-00805f9b34fb": "Ringer Setting",
    "00002a42-0000-1000-8000-00805f9b34fb": "Alert Category ID Bit Mask",
    "00002a43-0000-1000-8000-00805f9b34fb": "Alert Category ID",
    "00002a44-0000-1000-8000-00805f9b34fb": "Alert Notification Control Point",
    "00002a45-0000-1000-8000-00805f9b34fb": "Unread Alert Status",
    "00002a46-0000-1000-8000-00805f9b34fb": "New Alert",
    "00002a47-0000-1000-8000-00805f9b34fb": "Supported New Alert Category",
    "00002a48-0000-1000-8000-00805f9b34fb": "Supported Unread Alert Category",
    "00002a49-0000-1000-8000-00805f9b34fb": "Blood Pressure Feature",
    "00002a4a-0000-1000-8000-00805f9b34fb": "HID Information",
    "00002a4b-0000-1000-8000-00805f9b34fb": "Report Map",
    "00002a4c-0000-1000-8000-00805f9b34fb": "HID Control Point",
    "00002a4d-0000-1000-8000-00805f9b34fb": "Report",
    "00002a4e-0000-1000-8000-00805f9b34fb": "Protocol Mode",
    "00002a4f-0000-1000-8000-00805f9b34fb": "Scan Interval Window",
    "00002a50-0000-1000-8000-00805f9b34fb": "PnP ID",
    "00002a51-0000-1000-8000-00805f9b34fb": "Glucose Feature",
    "00002a52-0000-1000-8000-00805f9b34fb": "Record Access Control Point",
    "00002a53-0000-1000-8000-00805f9b34fb": "RSC Measurement",
    "00002a54-0000-1000-8000-00805f9b34fb": "RSC Feature",
    "00002a55-0000-1000-8000-00805f9b34fb": "SC Control Point",
    "00002a56-0000-1000-8000-00805f9b34fb": "Digital",
    "00002a58-0000-1000-8000-00805f9b34fb": "Analog",
    "00002a5a-0000-1000-8000-00805f9b34fb": "Aggregate",
    "00002a5b-0000-1000-8000-00805f9b34fb": "CSC Measurement",
    "00002a5c-0000-1000-8000-00805f9b34fb": "CSC Feature",
    "00002a5d-0000-1000-8000-00805f9b34fb": "Sensor Location",
    "00002a63-0000-1000-8000-00805f9b34fb": "Cycling Power Measurement",
    "00002a64-0000-1000-8000-00805f9b34fb": "Cycling Power Vector",
    "00002a65-0000-1000-8000-00805f9b34fb": "Cycling Power Feature",
    "00002a66-0000-1000-8000-00805f9b34fb": "Cycling Power Control Point",
    "00002a67-0000-1000-8000-00805f9b34fb": "Location and Speed",
    "00002a68-0000-1000-8000-00805f9b34fb": "Navigation",
    "00002a69-0000-1000-8000-00805f9b34fb": "Position Quality",
    "00002a6a-0000-1000-8000-00805f9b34fb": "LN Feature",
    "00002a6b-0000-1000-8000-00805f9b34fb": "LN Control Point",
    "00002a6c-0000-1000-8000-00805f9b34fb": "Elevation",
    "00002a6d-0000-1000-8000-00805f9b34fb": "Pressure",
    "00002a6e-0000-1000-8000-00805f9b34fb": "Temperature",
    "00002a6f-0000-1000-8000-00805f9b34fb": "Humidity",
    "00002a70-0000-1000-8000-00805f9b34fb": "True Wind Speed",
    "00002a71-0000-1000-8000-00805f9b34fb": "True Wind Direction",
    "00002a72-0000-1000-8000-00805f9b34fb": "Apparent Wind Speed",
    "00002a73-0000-1000-8000-00805f9b34fb": "Apparent Wind Direction",
    "00002a74-0000-1000-8000-00805f9b34fb": "Gust Factor",
    "00002a75-0000-1000-8000-00805f9b34fb": "Pollen Concentration",
    "00002a76-0000-1000-8000-00805f9b34fb": "UV Index",
    "00002a77-0000-1000-8000-00805f9b34fb": "Irradiance",
    "00002a78-0000-1000-8000-00805f9b34fb": "Rainfall",
    "00002a79-0000-1000-8000-00805f9b34fb": "Wind Chill",
    "00002a7a-0000-1000-8000-00805f9b34fb": "Heat Index",
    "00002a7b-0000-1000-8000-00805f9b34fb": "Dew Point",
    "00002a7d-0000-1000-8000-00805f9b34fb": "Descriptor Value Changed",
    "00002a7e-0000-1000-8000-00805f9b34fb": "Aerobic Heart Rate Lower Limit",
    "00002a7f-0000-1000-8000-00805f9b34fb": "Aerobic Threshold",
    "00002a80-0000-1000-8000-00805f9b34fb": "Age",
    "00002a81-0000-1000-8000-00805f9b34fb": "Anaerobic Heart Rate Lower Limit",
    "00002a82-0000-1000-8000-00805f9b34fb": "Anaerobic Heart Rate Upper Limit",
    "00002a83-0000-1000-8000-00805f9b34fb": "Anaerobic Threshold",
    "00002a84-0000-1000-8000-00805f9b34fb": "Aerobic Heart Rate Upper Limit",
    "00002a85-0000-1000-8000-00805f9b34fb": "Date of Birth",
    "00002a86-0000-1000-8000-00805f9b34fb": "Date of Threshold Assessment",
    "00002a87-0000-1000-8000-00805f9b34fb": "Email Address",
    "00002a88-0000-1000-8000-00805f9b34fb": "Fat Burn Heart Rate Lower Limit",
    "00002a89-0000-1000-8000-00805f9b34fb": "Fat Burn Heart Rate Upper Limit",
    "00002a8a-0000-1000-8000-00805f9b34fb": "First Name",
    "00002a8b-0000-1000-8000-00805f9b34fb": "Five Zone Heart Rate Limits",
    "00002a8c-0000-1000-8000-00805f9b34fb": "Gender",
    "00002a8d-0000-1000-8000-00805f9b34fb": "Heart Rate Max",
    "00002a8e-0000-1000-8000-00805f9b34fb": "Height",
    "00002a8f-0000-1000-8000-00805f9b34fb": "Hip Circumference",
    "00002a90-0000-1000-8000-00805f9b34fb": "Last Name",
    "00002a91-0000-1000-8000-00805f9b34fb": "Maximum Recommended Heart Rate",
    "00002a92-0000-1000-8000-00805f9b34fb": "Resting Heart Rate",
    "00002a93-0000-1000-8000-00805f9b34fb": "Sport Type for Aerobic and Anaerobic Thresholds",
    "00002a94-0000-1000-8000-00805f9b34fb": "Three Zone Heart Rate Limits",
    "00002a95-0000-1000-8000-00805f9b34fb": "Two Zone Heart Rate Limit",
    "00002a96-0000-1000-8000-00805f9b34fb": "VO2 Max",
    "00002a97-0000-1000-8000-00805f9b34fb": "Waist Circumference",
    "00002a98-0000-1000-8000-00805f9b34fb": "Weight",
    "00002a99-0000-1000-8000-00805f9b34fb": "Database Change Increment",
    "00002a9a-0000-1000-8000-00805f9b34fb": "User Index",
    "00002a9b-0000-1000-8000-00805f9b34fb": "Body Composition Feature",
    "00002a9c-0000-1000-8000-00805f9b34fb": "Body Composition Measurement",
    "00002a9d-0000-1000-8000-00805f9b34fb": "Weight Measurement",
    "00002a9e-0000-1000-8000-00805f9b34fb": "Weight Scale Feature",
    "00002a9f-0000-1000-8000-00805f9b34fb": "User Control Point",
    "00002aa0-0000-1000-8000-00805f9b34fb": "Magnetic Flux Density - 2D",
    "00002aa1-0000-1000-8000-00805f9b34fb": "Magnetic Flux Density - 3D",
    "00002aa2-0000-1000-8000-00805f9b34fb": "Language",
    "00002aa3-0000-1000-8000-00805f9b34fb": "Barometric Pressure Trend",
    "00002aa4-0000-1000-8000-00805f9b34fb": "Bond Management Control Point",
    "00002aa5-0000-1000-8000-00805f9b34fb": "Bond Management Feature",
    "00002aa6-0000-1000-8000-00805f9b34fb": "Central Address Resolution",
    "00002aa7-0000-1000-8000-00805f9b34fb": "CGM Measurement",
    "00002aa8-0000-1000-8000-00805f9b34fb": "CGM Feature",
    "00002aa9-0000-1000-8000-00805f9b34fb": "CGM Status",
    "00002aaa-0000-1000-8000-00805f9b34fb": "CGM Session Start Time",
    "00002aab-0000-1000-8000-00805f9b34fb": "CGM Session Run Time",
    "00002aac-0000-1000-8000-00805f9b34fb": "CGM Specific Ops Control Point",
    "00002aad-0000-1000-8000-00805f9b34fb": "Indoor Positioning Configuration",
    "00002aae-0000-1000-8000-00805f9b34fb": "Latitude",
    "00002aaf-0000-1000-8000-00805f9b34fb": "Longitude",
    "00002ab0-0000-1000-8000-00805f9b34fb": "Local North Coordinate",
    "00002ab1-0000-1000-8000-00805f9b34fb": "Local East Coordinate",
    "00002ab2-0000-1000-8000-00805f9b34fb": "Floor Number",
    "00002ab3-0000-1000-8000-00805f9b34fb": "Altitude",
    "00002ab4-0000-1000-8000-00805f9b34fb": "Uncertainty",
    "00002ab5-0000-1000-8000-00805f9b34fb": "Location Name",
    "00002ab6-0000-1000-8000-00805f9b34fb": "URI",
    "00002ab7-0000-1000-8000-00805f9b34fb": "HTTP Headers",
    "00002ab8-0000-1000-8000-00805f9b34fb": "HTTP Status Code",
    "00002ab9-0000-1000-8000-00805f9b34fb": "HTTP Entity Body",
    "00002aba-0000-1000-8000-00805f9b34fb": "HTTP Control Point",
    "00002abb-0000-1000-8000-00805f9b34fb": "HTTPS Security",
    "00002abc-0000-1000-8000-00805f9b34fb": "TDS Control Point",
    "00002abd-0000-1000-8000-00805f9b34fb": "OTS Feature",
    "00002abe-0000-1000-8000-00805f9b34fb": "Object Name",
    "00002abf-0000-1000-8000-00805f9b34fb": "Object Type",
    "00002ac0-0000-1000-8000-00805f9b34fb": "Object Size",
    "00002ac1-0000-1000-8000-00805f9b34fb": "Object First-Created",
    "00002ac2-0000-1000-8000-00805f9b34fb": "Object Last-Modified",
    "00002ac3-0000-1000-8000-00805f9b34fb": "Object ID",
    "00002ac4-0000-1000-8000-00805f9b34fb": "Object Properties",
    "00002ac5-0000-1000-8000-00805f9b34fb": "Object Action Control Point",
    "00002ac6-0000-1000-8000-00805f9b34fb": "Object List Control Point",
    "00002ac7-0000-1000-8000-00805f9b34fb": "Object List Filter",
    "00002ac8-0000-1000-8000-00805f9b34fb": "Object Changed",
    "00002ac9-0000-1000-8000-00805f9b34fb": "Resolvable Private Address Only",
    "00002acc-0000-1000-8000-00805f9b34fb": "Fitness Machine Feature",
    "00002acd-0000-1000-8000-00805f9b34fb": "Treadmill Data",
    "00002ace-0000-1000-8000-00805f9b34fb": "Cross Trainer Data",
    "00002acf-0000-1000-8000-00805f9b34fb": "Step Climber Data",
    "00002ad0-0000-1000-8000-00805f9b34fb": "Stair Climber Data",
    "00002ad1-0000-1000-8000-00805f9b34fb": "Rower Data",
    "00002ad2-0000-1000-8000-00805f9b34fb": "Indoor Bike Data",
    "00002ad3-0000-1000-8000-00805f9b34fb": "Training Status",
    "00002ad4-0000-1000-8000-00805f9b34fb": "Supported Speed Range",
    "00002ad5-0000-1000-8000-00805f9b34fb": "Supported Inclination Range",
    "00002ad6-0000-1000-8000-00805f9b34fb": "Supported Resistance Level Range",
    "00002ad7-0000-1000-8000-00805f9b34fb": "Supported Heart Rate Range",
    "00002ad8-0000-1000-8000-00805f9b34fb": "Supported Power Range",
    "00002ad9-0000-1000-8000-00805f9b34fb": "Fitness Machine Control Point",
    "00002ada-0000-1000-8000-00805f9b34fb": "Fitness Machine Status",
    "00002adb-0000-1000-8000-00805f9b34fb": "Mesh Provisioning Data In",
    "00002adc-0000-1000-8000-00805f9b34fb": "Mesh Provisioning Data Out",
    "00002add-0000-1000-8000-00805f9b34fb": "Mesh Proxy Data In",
    "00002ade-0000-1000-8000-00805f9b34fb": "Mesh Proxy Data Out",
}

def get_service_name(uuid: str) -> str:
    """Возвращает читаемое имя сервиса по UUID"""
    uuid_lower = uuid.lower()
    
    # Проверяем стандартные сервисы
    if uuid_lower in STANDARD_SERVICES:
        return STANDARD_SERVICES[uuid_lower]
    
    # Проверяем ASHA сервис
    if uuid_lower == "0000fd0f-0000-1000-8000-00805f9b34fb":
        return "ASHA Service"
    
    # Если UUID короткий (16-bit), показываем в коротком формате
    if uuid_lower.startswith("0000") and uuid_lower.endswith("-0000-1000-8000-00805f9b34fb"):
        short_uuid = uuid_lower[4:8].upper()
        return f"Unknown Service (0x{short_uuid})"
    
    # Для длинных UUID показываем первые 8 символов
    if len(uuid_lower) > 8:
        return f"Custom Service ({uuid_lower[:8]}...)"
    
    return uuid_lower

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
    
    # Если значение состоит только из нулей
    if all(b == 0 for b in value):
        return "<all zeros>"
    
    # Пытаемся декодировать как строку UTF-8
    try:
        text = value.decode('utf-8')
        # Убираем непечатаемые символы и пробелы по краям
        text = ''.join(char for char in text if char.isprintable() or char in '\n\r\t')
        text = text.strip()
        
        if text:
            # Если строка короткая, показываем полностью
            if len(text) <= 80:
                return f'"{text}"'
            else:
                # Показываем первые 60 символов и длину
                return f'"{text[:60]}..." (length: {len(text)} chars)'
    except UnicodeDecodeError:
        pass
    
    # Пытаемся декодировать как ASCII
    try:
        text = value.decode('ascii', errors='ignore')
        text = ''.join(char for char in text if char.isprintable() or char in '\n\r\t')
        text = text.strip()
        
        if text:
            if len(text) <= 80:
                return f'[ASCII] "{text}"'
            else:
                return f'[ASCII] "{text[:60]}..." (length: {len(text)} chars)'
    except:
        pass
    
    # Если не строка, показываем hex и анализируем структуру
    hex_str = value.hex().upper()
    
    # Если это короткое значение (<= 8 байт), показываем в разных форматах
    if len(value) <= 8:
        formats = []
        
        # 1. Hex
        formats.append(f"0x{hex_str}")
        
        # 2. Decimal
        if len(value) <= 4:
            if len(value) == 2:
                int_val = struct.unpack('<H', value)[0]
                formats.append(f"dec: {int_val}")
            elif len(value) == 4:
                int_val = struct.unpack('<I', value)[0]
                formats.append(f"dec: {int_val}")
        
        # 3. ASCII representation
        ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in value)
        if any(32 <= b < 127 for b in value):
            formats.append(f"ASCII: '{ascii_repr}'")
        
        return " | ".join(formats)
    else:
        # Для длинных значений показываем начало и конец
        if len(hex_str) > 40:
            return f"0x{hex_str[:20]}...{hex_str[-20:]} (length: {len(value)} bytes)"
        else:
            return f"0x{hex_str} (length: {len(value)} bytes)"

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