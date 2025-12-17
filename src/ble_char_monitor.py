#!/usr/bin/env python3
"""
IAI_RX_SET BLE Monitor с автоматическим периодическим чтением
"""

import asyncio
import struct
import time
from bleak import BleakScanner, BleakClient
from bleak.exc import BleakError

SCAN_SECONDS = 6.0
BRAND_NAMES = ["Prima", "Runa", "Runa", "RunaPro", "Pronto", "Qtone"]

class IAIMonitorAuto:
    def __init__(self):
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
        
    def detection_callback(self, device, advertisement_data):
        self.devices[getattr(device, "address", "<no-address>")] = (device, advertisement_data)
    
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
        await asyncio.sleep(seconds)
        await scanner.stop()
        
        if not self.devices:
            print("No devices found.")
            return False
        
        print(f"\nFound {len(self.devices)} device(s):")
        print(f"{'='*60}")
        
        # Фильтруем только BRAND_NAMES устройства
        brand_devices = []
        other_devices = []
        
        for addr, (device, _) in self.devices.items():
            name = self.get_device_name(device)
            rssi = getattr(device, "rssi", "N/A")
            
            if any(brand in name for brand in BRAND_NAMES):
                brand_devices.append((addr, device, name, rssi))
            else:
                other_devices.append((addr, device, name, rssi))
        
        brand_devices.sort(key=lambda x: x[2].lower())
        
        # Выводим Prima устройства
        print("IAI DEVICES:")
        for i, (addr, device, name, rssi) in enumerate(brand_devices, 1):
            print(f"{i:<3} {name:<25} {addr:<20} RSSI: {rssi}")
        
        # Выводим другие устройства
        if other_devices:
            print(f"\nOTHER DEVICES ({len(other_devices)}):")
            for i, (addr, device, name, rssi) in enumerate(other_devices, len(brand_devices) + 1):
                print(f"{i:<3} {name:<25} {addr:<20} RSSI: {rssi}")
        
        print(f"{'='*60}")
        
        # Обновляем словарь
        all_displayed = brand_devices + other_devices
        self.devices = {addr: (device, None) for addr, device, name, rssi in all_displayed}
        
        return True
    
    def clean_rtt_output(self, value: bytes) -> str:
        """Очищает RTT вывод"""
        if not value:
            return ""
        
        # Декодируем
        try:
            text = value.decode('utf-8', errors='ignore')
        except:
            try:
                text = value.decode('ascii', errors='ignore')
            except:
                return value.hex().upper()
        
        # Убираем ANSI escape sequences
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        text = ansi_escape.sub('', text)
        
        # Очищаем управляющие символы
        cleaned = []
        for char in text:
            if char == '\n' or char == '\r' or char == '\t':
                cleaned.append(char)
            elif ord(char) >= 32 or char == '\t':
                cleaned.append(char)
            elif char == '\x00':
                continue
            else:
                cleaned.append(' ')
        
        result = ''.join(cleaned)
        
        # Убираем лишние пробелы
        lines = result.split('\n')
        cleaned_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped:
                cleaned_lines.append(stripped)
            elif line == '':
                cleaned_lines.append('')
        
        return '\n'.join(cleaned_lines)
    
    def notification_handler(self, sender, data):
        """Обработчик уведомлений"""
        self.notification_count += 1
        clean_data = self.clean_rtt_output(data)
        
        if clean_data:
            timestamp = time.strftime("%H:%M:%S", time.localtime())
            print(f"\n[{timestamp}] NOTIFICATION #{self.notification_count}:")
            print("-" * 40)
            print(clean_data)
            print("-" * 40)
    
    async def read_characteristic_value(self):
        """Читает текущее значение характеристики"""
        if not self.client or not self.client.is_connected or not self.target_char:
            return None
        
        try:
            value = await self.client.read_gatt_char(self.target_char.uuid)
            return self.clean_rtt_output(value)
        except Exception as e:
            return f"<read error: {e}>"
    
    async def auto_read_task(self):
        """Задача для автоматического чтения"""
        print(f"\nStarting auto-read every {self.auto_read_interval} seconds...")
        
        last_read_time = 0
        last_data_hash = None
        
        while self.auto_reading and self.client and self.client.is_connected:
            try:
                current_time = time.time()
                
                # Читаем с заданным интервалом
                if current_time - last_read_time >= self.auto_read_interval:
                    data = await self.read_characteristic_value()
                    last_read_time = current_time
                    
                    if data and data != "<read error: ...>":
                        # Проверяем, изменились ли данные
                        data_hash = hash(data)
                        
                        if data_hash != last_data_hash or self.read_count == 0:
                            self.read_count += 1
                            last_data_hash = data_hash
                            
                        #     timestamp = time.strftime("%H:%M:%S", time.localtime())
                        #     print(f"\n[{timestamp}] AUTO-READ #{self.read_count}:")
                        #     print("-" * 40)
                            print(data)
                        #     print("-" * 40)
                        # else:
                        #     print(f"[{timestamp}] Data unchanged, skipping display")
                    
                    elif "<read error" in str(data):
                        print(f"[{time.strftime('%H:%M:%S')}] Read error, retrying...")
                
                await asyncio.sleep(0.1)  # Короткая пауза
                
            except Exception as e:
                print(f"Auto-read error: {e}")
                await asyncio.sleep(1)
    
    async def find_and_monitor_iai_rx_set(self, device_address, device_name):
        """Находит IAI_RX_SET и начинает мониторинг"""
        print(f"\n{'='*60}")
        print(f"Connecting to: {device_name}")
        print(f"Address: {device_address}")
        print(f"Target: {self.target_description}")
        print(f"{'='*60}")
        
        try:
            self.client = BleakClient(device_address, timeout=10.0)
            
            print("Connecting...")
            await self.client.connect()
            
            if not self.client.is_connected:
                print("✗ Connection failed")
                return False
            
            print("✓ Connected successfully")
            
            # Находим сервисы
            print("\nDiscovering services...")
            try:
                await self.client.discover()
            except AttributeError:
                pass
            
            # Ищем целевую характеристику
            self.target_char = None
            
            try:
                services = self.client.services
            except AttributeError:
                try:
                    services = await self.client.get_services()
                except AttributeError:
                    services = getattr(self.client, '_services', [])
            
            if isinstance(services, list):
                services_list = services
            else:
                services_list = list(services) if hasattr(services, '__iter__') else []
            
            print(f"Found {len(services_list)} service(s)")
            
            for service in services_list:
                try:
                    characteristics = service.characteristics
                except AttributeError:
                    continue
                
                for char in characteristics:
                    # Проверяем по UUID
                    if char.uuid.lower() == self.target_char_uuid.lower():
                        self.target_char = char
                        break
                    
                    # Проверяем по описанию
                    try:
                        descriptors = char.descriptors if hasattr(char, 'descriptors') else []
                        for desc in descriptors:
                            if desc.uuid.lower() == "00002901-0000-1000-8000-00805f9b34fb":
                                desc_value = await self.client.read_gatt_descriptor(desc.handle)
                                try:
                                    desc_text = desc_value.decode('utf-8', errors='ignore').strip()
                                    if desc_text == self.target_description:
                                        self.target_char = char
                                        break
                                except:
                                    pass
                    except:
                        pass
                    
                    if self.target_char:
                        break
                
                if self.target_char:
                    break
            
            if not self.target_char:
                print(f"\n✗ Characteristic '{self.target_description}' not found")
                
                # Показываем характеристики с read для отладки
                print("\nAvailable characteristics with read support:")
                read_chars = []
                for service in services_list:
                    try:
                        characteristics = service.characteristics
                    except AttributeError:
                        continue
                    
                    for char in characteristics:
                        if "read" in char.properties:
                            description = char.uuid
                            try:
                                descriptors = char.descriptors if hasattr(char, 'descriptors') else []
                                for desc in descriptors:
                                    if desc.uuid.lower() == "00002901-0000-1000-8000-00805f9b34fb":
                                        desc_value = await self.client.read_gatt_descriptor(desc.handle)
                                        try:
                                            desc_text = desc_value.decode('utf-8', errors='ignore').strip()
                                            if desc_text:
                                                description = desc_text
                                        except:
                                            pass
                            except:
                                pass
                            
                            read_chars.append((char.uuid, description, char.handle))
                
                if read_chars:
                    for uuid, desc, handle in read_chars:
                        print(f"  - {desc} [{uuid[:8]}...] Handle: 0x{handle:04X}")
                
                await self.client.disconnect()
                return False
            
            print(f"\n✓ Found target characteristic")
            print(f"  UUID: {self.target_char.uuid}")
            print(f"  Handle: 0x{self.target_char.handle:04X}")
            print(f"  Properties: {list(self.target_char.properties)}")
            
            # Читаем текущее значение
            print("\nReading initial value...")
            initial_value = await self.read_characteristic_value()
            if initial_value and "<read error" not in str(initial_value):
                timestamp = time.strftime("%H:%M:%S", time.localtime())
                print(f"\n[{timestamp}] INITIAL VALUE:")
                print("-" * 40)
                print(initial_value)
                print("-" * 40)
                self.read_count = 1
            else:
                print("(empty or error)")
                self.read_count = 0
            
            # Настраиваем уведомления если поддерживается
            if "notify" in self.target_char.properties:
                print("\nEnabling notifications...")
                await self.client.start_notify(self.target_char.uuid, self.notification_handler)
                
                # Проверяем CCCD
                try:
                    descriptors = self.target_char.descriptors if hasattr(self.target_char, 'descriptors') else []
                    for desc in descriptors:
                        if desc.uuid.lower() == "00002902-0000-1000-8000-00805f9b34fb":
                            cccd_value = await self.client.read_gatt_descriptor(desc.handle)
                            if len(cccd_value) >= 2:
                                cccd_int = struct.unpack('<H', cccd_value[:2])[0]
                                if cccd_int & 0x0001:
                                    print(f"✓ Notifications enabled (CCCD: 0x{cccd_int:04X})")
                                else:
                                    print(f"⚠ CCCD disabled (0x{cccd_int:04X})")
                            break
                except Exception as e:
                    print(f"⚠ Could not check CCCD: {e}")
            else:
                print("⚠ Characteristic does not support notifications")
            
            print(f"\n{'='*60}")
            print("MONITORING STARTED")
            print(f"{'='*60}")
            print("Auto-reading configuration:")
            print(f"  Interval: {self.auto_read_interval} seconds")
            print(f"  Display only when data changes")
            print("\nCommands during monitoring:")
            print("  'r' - Manual read (force)")
            print("  'a' - Toggle auto-read (currently: ON)")
            print("  '+' - Increase auto-read interval")
            print("  '-' - Decrease auto-read interval")
            print("  'i' - Show current interval")
            print("  'q' - Stop monitoring")
            print("  Ctrl+C - Emergency stop")
            print(f"{'='*60}\n")
            
            self.monitoring = True
            self.auto_reading = True
            self.notification_count = 0
            self.start_time = time.time()
            
            # Запускаем задачу авто-чтения
            auto_read_task = asyncio.create_task(self.auto_read_task())
            
            # Основной цикл с поддержкой команд
            try:
                while self.monitoring and self.client.is_connected:
                    # Обработка ввода
                    try:
                        user_input = await asyncio.wait_for(
                            asyncio.get_event_loop().run_in_executor(
                                None, input, ""
                            ),
                            timeout=0.5
                        )
                        
                        if user_input.strip().lower() == 'q':
                            print("Stopping monitoring...")
                            self.monitoring = False
                            self.auto_reading = False
                            break
                        
                        elif user_input.strip().lower() == 'r':
                            # Ручное чтение
                            data = await self.read_characteristic_value()
                            if data and "<read error" not in str(data):
                                timestamp = time.strftime("%H:%M:%S", time.localtime())
                                print(f"\n[{timestamp}] MANUAL READ:")
                                print("-" * 40)
                                print(data)
                                print("-" * 40)
                            else:
                                print(f"✗ Read failed: {data}")
                        
                        elif user_input.strip().lower() == 'a':
                            # Включить/выключить авто-чтение
                            self.auto_reading = not self.auto_reading
                            status = "ON" if self.auto_reading else "OFF"
                            print(f"\nAuto-read: {status}")
                            
                            if self.auto_reading:
                                # Перезапускаем задачу авто-чтения
                                auto_read_task.cancel()
                                try:
                                    await auto_read_task
                                except asyncio.CancelledError:
                                    pass
                                auto_read_task = asyncio.create_task(self.auto_read_task())
                        
                        elif user_input.strip() == '+':
                            # Увеличить интервал
                            self.auto_read_interval = min(30.0, self.auto_read_interval + 0.5)
                            print(f"\nAuto-read interval: {self.auto_read_interval:.1f}s")
                        
                        elif user_input.strip() == '-':
                            # Уменьшить интервал
                            self.auto_read_interval = max(0.5, self.auto_read_interval - 0.5)
                            print(f"\nAuto-read interval: {self.auto_read_interval:.1f}s")
                        
                        elif user_input.strip().lower() == 'i':
                            print(f"\nCurrent auto-read interval: {self.auto_read_interval:.1f}s")
                        
                        elif user_input.strip():
                            print("\nCommands: r=read, a=toggle auto, +/-=interval, i=interval, q=quit")
                            
                    except asyncio.TimeoutError:
                        # Таймаут - ничего не введено
                        continue
                    except (EOFError, KeyboardInterrupt):
                        print("\nInterrupted")
                        self.monitoring = False
                        self.auto_reading = False
                        break
                    
            except KeyboardInterrupt:
                print("\n\nMonitoring interrupted")
                self.monitoring = False
                self.auto_reading = False
            except Exception as e:
                print(f"\nError in monitoring loop: {e}")
                self.monitoring = False
                self.auto_reading = False
            
            finally:
                # Отменяем задачу авто-чтения
                self.auto_reading = False
                auto_read_task.cancel()
                try:
                    await auto_read_task
                except asyncio.CancelledError:
                    pass
            
            return True
            
        except asyncio.TimeoutError:
            print("✗ Connection timeout")
            return False
        except BleakError as e:
            print(f"✗ Bleak error: {e}")
            return False
        except Exception as e:
            print(f"✗ Error: {type(e).__name__}: {e}")
            return False
    
    async def stop_monitoring(self):
        """Останавливает мониторинг"""
        if self.client and self.client.is_connected:
            print("\nStopping monitoring...")
            self.monitoring = False
            self.auto_reading = False
            
            # Останавливаем уведомления
            try:
                if hasattr(self.client, 'services'):
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
    
    async def run(self):
        """Основной цикл программы"""
        print(f"{'='*60}")
        print(f"IAI_RX_SET BLE MONITOR WITH AUTO-READ")
        print(f"Auto-read interval: {self.auto_read_interval}s")
        print(f"{'='*60}")
        
        while True:
            # Сканируем устройства
            if not await self.scan_devices():
                print("\nNo Prima devices found.")
                choice = input("Press Enter to rescan or 'q' to quit: ").strip().lower()
                if choice == 'q':
                    break
                continue
            
            # Выбираем устройство
            try:
                devices_list = list(self.devices.keys())
                
                while True:
                    try:
                        choice = input("\nEnter device number to monitor (l=rescan, q=quit, h=help): ").strip().lower()
                        
                        if choice == 'q':
                            return
                        elif choice == 'l':
                            break
                        elif choice == 'h':
                            print("\nHelp:")
                            print("  Enter number - monitor specific device")
                            print("  l - rescan devices")
                            print("  q - quit program")
                            print("  During monitoring:")
                            print("    r - manual read")
                            print("    a - toggle auto-read")
                            print("    + - increase interval")
                            print("    - - decrease interval")
                            print("    i - show interval")
                            print("    q - stop monitoring")
                            continue
                        elif choice.isdigit():
                            device_num = int(choice)
                            
                            if 1 <= device_num <= len(devices_list):
                                device_addr = devices_list[device_num - 1]
                                device, _ = self.devices[device_addr]
                                device_name = self.get_device_name(device)
                                
                                # Запускаем мониторинг
                                success = await self.find_and_monitor_iai_rx_set(device_addr, device_name)
                                
                                # После мониторинга
                                if success:
                                    print("\nMonitoring stopped.")
                                    choice = input("Press Enter to return to device list, 'l' to rescan, or 'q' to quit: ").strip().lower()
                                    
                                    if choice == 'q':
                                        await self.stop_monitoring()
                                        return
                                    elif choice == 'l':
                                        await self.stop_monitoring()
                                        break
                                    else:
                                        await self.stop_monitoring()
                                        break
                                else:
                                    await self.stop_monitoring()
                                    print("\nFailed to monitor. Try another device?")
                                    continue
                                
                            else:
                                print(f"Invalid number. Please enter 1-{len(devices_list)}")
                        else:
                            print("Invalid input. Enter a number, 'l', 'q', or 'h'")
                            
                    except KeyboardInterrupt:
                        print("\n\nReturning to device selection...")
                        await self.stop_monitoring()
                        break
                    except Exception as e:
                        print(f"Error: {e}")
                        await self.stop_monitoring()
                
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

"""     Основные особенности:
1. Автоматическое чтение каждые 2 секунды (настраивается)
2. Умное отображение - показывает данные только когда они изменились
3. Команды управления:
    r - ручное чтение
    a - вкл/выкл авто-чтение
    + - увеличить интервал
    - - уменьшить интервал
    i - показать текущий интервал
    q - выход
4. Временные метки для каждого чтения
5. Статистика сессии - количество чтений и уведомлений

Как использовать:
1. Запустите скрипт
2. Выберите устройство
3. Скрипт автоматически начнет читать значение каждые 2 секунды
4. Данные выводятся только при изменении
5. Используйте команды для управления """