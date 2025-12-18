#!/usr/bin/env python3
"""
IAI_RX_SET BLE Monitor с авто-чтением
Добавлено:
 - 's' — переключение сортировки (name / RSSI)
 - 't' — задать порог RSSI (фильтрация устройств с RSSI ниже порога)
"""

import asyncio
import struct
import time
from bleak import BleakScanner, BleakClient
from bleak.exc import BleakError

SCAN_SECONDS = 20.0
BRAND_NAMES = ["Prima", "Runa", "Runa", "RunaPro", "Pronto", "Qtone"]

class IAIMonitorAuto:
    def __init__(self):
        # self.devices: addr -> (device, advertisement_data, rssi)
        self.devices = {}
        self.client = None
        self.monitoring = False
        self.auto_reading = False
        self.notification_count = 0
        self.read_count = 0
        self.start_time = 0
        self.target_char_uuid = "ab09bbda-c513-430b-a23a-dd442b65d048"
        self.target_description = "IAI_RX_SET"
        self.target_char = None
        self.auto_read_interval = 2.0  # Интервал авто-чтения в секундах
        self.progress_bar_len = 60
        self.progress_fill = "█"   # заполненный прямоугольник U+2588
        self.progress_empty = " "  # пустой символ

        # Новые опции
        self.sort_by_rssi = False   # False = сортировка по имени, True = по RSSI (desc)
        self.rssi_threshold = None  # None = без фильтра, иначе int (например -80)

    def detection_callback(self, device, advertisement_data):
        rssi = getattr(advertisement_data, "rssi", None)
        self.devices[getattr(device, "address", "<no-address>")] = (device, advertisement_data, rssi)

    def get_device_name(self, device):
        name = getattr(device, "name", None)
        return name if name else "<no-name>"

    async def scan_devices(self, seconds=SCAN_SECONDS):
        print(f"\n{'='*60}")
        print(f"Scanning for BLE devices ({seconds} seconds)...")
        print(f"{'='*60}")

        self.devices.clear()
        scanner = BleakScanner(detection_callback=self.detection_callback)

        await scanner.start()
        # Показываем прогресс-бар в одной строке
        start = time.time()
        per_sec = self.progress_bar_len / seconds
        filled = 0
        try:
            while True:
                elapsed = time.time() - start
                if elapsed >= seconds:
                    break
                # вычисляем сколько символов заполнено
                new_filled = int(elapsed * per_sec)
                if new_filled != filled:
                    filled = new_filled
                    bar = self.progress_fill * filled + self.progress_empty * (self.progress_bar_len - filled)
                    print(f"\r{bar} {int(elapsed):2d}/{int(seconds)}s", end="", flush=True)
                await asyncio.sleep(0.1)
        finally:
            # завершить строку и остановить сканер
            print(f"\r{'█'*self.progress_bar_len} {int(seconds)}/{int(seconds)}s")
            await scanner.stop()


        if not self.devices:
            print("No devices found.")
            return False

        print(f"\nFound {len(self.devices)} device(s). IAI brand:")
        print(f"{'='*60}")

        brand_devices = []
        other_devices = []

        for addr, (device, advertisement_data, rssi) in self.devices.items():
            name = self.get_device_name(device)
            if rssi is None:
                rssi = getattr(device, "rssi", "N/A")
            entry = (addr, device, advertisement_data, name, rssi)
            if any(brand in name for brand in BRAND_NAMES):
                brand_devices.append(entry)
            else:
                other_devices.append(entry)

        # Применяем фильтр по порогу RSSI (если задан)
        def rssi_value(e):
            rv = e[4]
            try:
                return int(rv)
            except Exception:
                return None

        if self.rssi_threshold is not None:
            def keep(e):
                rv = rssi_value(e)
                return rv is not None and rv >= self.rssi_threshold
            brand_devices = [e for e in brand_devices if keep(e)]
            other_devices = [e for e in other_devices if keep(e)]

        # Сортировка: по имени или по RSSI (desc)
        if self.sort_by_rssi:
            brand_devices.sort(key=lambda x: (rssi_value(x) is None, -(rssi_value(x) or -9999)))
        else:
            brand_devices.sort(key=lambda x: x[3].lower())

        print("IAI DEVICES:")
        for i, (addr, device, advertisement_data, name, rssi) in enumerate(brand_devices, 1):
            print(f"{i:<3} {name:<25} {addr:<20} RSSI: {rssi}")

        print(f"{'='*60}")

        all_displayed = brand_devices + other_devices
        self.devices = {addr: (device, advertisement_data, rssi) for (addr, device, advertisement_data, name, rssi) in all_displayed}

        return True

    async def stop_monitoring(self):
        """Останавливает мониторинг"""
        if self.client and getattr(self.client, "is_connected", False):
            print("\nStopping monitoring...")
            self.monitoring = False
            self.auto_reading = False

            # Останавливаем уведомления
            try:
                if hasattr(self.client, 'services') and self.client.services:
                    for service in self.client.services:
                        for char in service.characteristics:
                            if "notify" in char.properties:
                                try:
                                    await self.client.stop_notify(char.uuid)
                                except:
                                    pass
            except:
                pass

            try:
                await asyncio.sleep(0.5)
                print("Disconnecting...")
                await self.client.disconnect()
                print("✓ Disconnected")
            except Exception as e:
                print(f"⚠ Error during disconnect: {e}")

            duration = time.time() - self.start_time if self.start_time > 0 else 0
            print(f"\nSession summary:")
            print(f"  Duration: {duration:.1f} seconds")
            print(f"  Manual reads: {self.read_count}")
            print(f"  Notifications received: {self.notification_count}")
            print(f"{'='*60}")

        self.client = None
        self.target_char = None
        self.notification_count = 0
        self.read_count = 0
        self.start_time = 0

    def print_options(self):
        print("\nOptions after scan:")
        print("  Enter number - monitor specific device")
        print("  l - rescan devices")
        print("  q - quit program")
        #print("  h - help")
        print("  s - toggle sort (name / RSSI)")
        print("  t - set RSSI threshold (filter out devices below threshold)")

    async def run(self):
        """Основной цикл программы"""
        while True:
            # Сканируем устройства
            if not await self.scan_devices():
                print("\nNo IAI devices found.")
                choice = input("Press Enter to rescan or 'q' to quit: ").strip().lower()
                if choice == 'q':
                    break
                continue

            # Выбираем устройство / опции
            try:
                devices_list = list(self.devices.keys())

                while True:
                    try:
                        self.print_options()
                        choice = input("\nEnter option: ").strip().lower()

                        if choice == 'q':
                            return
                        elif choice == 'l':
                            break
                        # elif choice == 'h':
                        #     print("\nHelp:")
                        #     print("  Enter number - monitor specific device")
                        #     print("  l - rescan devices")
                        #     print("  q - quit program")
                        #     print("  s - toggle sorting by name / RSSI")
                        #     print("  t - set RSSI threshold (e.g. -80). Empty to clear.")
                        elif choice == 's':
                            self.sort_by_rssi = not self.sort_by_rssi
                            mode = "RSSI" if self.sort_by_rssi else "Name"
                            print(f"Sorting by: {mode}. Rescanning...")
                            await self.scan_devices()
                            continue
                        elif choice == 't':
                            # Ввод порога RSSI
                            val = input("Enter RSSI threshold (e.g. -80). Leave empty to clear: ").strip()
                            if val == "":
                                self.rssi_threshold = None
                                print("RSSI threshold cleared. Rescanning...")
                                await self.scan_devices()
                                continue
                            try:
                                thr = int(val)
                                self.rssi_threshold = thr
                                print(f"RSSI threshold set to {thr}. Rescanning...")
                                await self.scan_devices()
                                continue
                            except ValueError:
                                print("Invalid value. Enter integer like -80.")
                                continue
                        else:
                            # Попытка распознать номер устройства
                            try:
                                idx = int(choice)
                                if idx < 1 or idx > len(devices_list):
                                    print("Invalid device number.")
                                    continue
                                selected_addr = devices_list[idx - 1]
                                # Здесь можно вставить логику подключения/мониторинга по выбранному адресу
                                print(f"Selected device #{idx}: {selected_addr}")
                                # Для краткости возвращаемся в начало (или реализуем подключение)
                                break
                            except ValueError:
                                print("Invalid input. Enter a number or one of the options.")
                                continue

                    except KeyboardInterrupt:
                        print("\n\nReturning to scan selection...")
                        await self.scan_devices()
                        break
                    except Exception as e:
                        print(f"Error - go to scan: {e}")
                        await self.scan_devices()

                if choice == 'l':
                    continue  # Пересканировать

            except KeyboardInterrupt:
                print("\n\nProgram interrupted")
                break
            except Exception as e:
                print(f"Error: {e}")

async def main():
    """Точка входа"""
    monitor = IAIMonitorAuto()
    try:
        await monitor.run()
    except KeyboardInterrupt:
        print("\n\nProgram stopped by user")
    except Exception as e:
        print(f"\nFatal error: {e}")
    finally:
        await monitor.stop_monitoring()
        print("\nGoodbye!")

if __name__ == "__main__":
    asyncio.run(main())
