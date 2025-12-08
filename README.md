## Launch: The script ble_scan.py first scans for 6 seconds and prints a list. Input:

- number — show the packet for the selected device (after displaying, it will return to the prompt),
- l — scan again and print the list of found devices,
- p - parse current ADV pack
- c - connect & explore services
- q — exit

## Requirements
- Python 3.9+
- Bluetooth adapter supported by your OS
- Windows/macOS/Linux may require system dependencies (updated drivers or Bluetooth packages)

## Installing Dependencies

python -m venv .venv
source .venv/bin/activate # Linux / macOS
.venv\Scripts\activate # Windows
pip install -r requirements.txt