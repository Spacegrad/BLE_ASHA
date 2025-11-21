""" import asyncio
from bleak import BleakScanner

async def main():
    devices = await BleakScanner.discover()
    for device in devices:
        print(device)


asyncio.run(main()) """
import asyncio
from bleak import BleakScanner

def detection_callback(device, advertisement_data):
    addr = getattr(device, "address", "<no-address>")
    name = getattr(device, "name", None) or "<no-name>"
    rssi = getattr(advertisement_data, "rssi", None)
    print(f"{addr}: {name}  RSSI={rssi}")
    if advertisement_data.manufacturer_data:
        for cid, b in advertisement_data.manufacturer_data.items():
            print(f"  0x{cid:04X}: {b.hex()}")
    if advertisement_data.service_data:
        for uuid, b in advertisement_data.service_data.items():
            print(f"  {uuid}: {b.hex()}")
    if advertisement_data.service_uuids:
        print("  Service UUIDs:", ", ".join(advertisement_data.service_uuids))
    print()

async def main():
    scanner = BleakScanner(detection_callback=detection_callback)
    await scanner.start()
    await asyncio.sleep(5.0)
    await scanner.stop()

if __name__ == "__main__":
    asyncio.run(main())
