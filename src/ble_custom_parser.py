import struct
import sys

def parse_iai_const_value(hex_string):
    """Парсит значение характеристики IAI_CONST"""
    
    # Убираем возможные префиксы и пробелы
    hex_string = hex_string.strip().replace('0x', '').replace(' ', '')
    
    # Проверяем длину
    if len(hex_string) != 36:  # 18 байт * 2 символа
        raise ValueError(f"Ожидается 36 hex-символов (18 байт), получено {len(hex_string)}")
    
    # Преобразуем в байты
    try:
        data = bytes.fromhex(hex_string)
    except ValueError:
        raise ValueError("Некорректный hex-формат")
    
    if len(data) != 18:
        raise ValueError(f"Ожидается 18 байт, получено {len(data)}")
    
    # Распаковываем структуру (little-endian)
    # Первые 4 байта: i8, i8, i8, u8
    volume_min = struct.unpack_from('<b', data, 0)[0]  # i8
    volume_mid = struct.unpack_from('<b', data, 1)[0]  # i8
    volume_max = struct.unpack_from('<b', data, 2)[0]  # i8
    volume_step = struct.unpack_from('<B', data, 3)[0]  # u8
    
    # Следующие 4 байта: u32 (серийный номер)
    serial_num = struct.unpack_from('<I', data, 4)[0]  # u32
    
    # Следующие 4 байта: u32 (серийный номер пары)
    pair_serial_num = struct.unpack_from('<I', data, 8)[0]  # u32
    
    # Следующие 2 байта: u16 (модель)
    model = struct.unpack_from('<H', data, 12)[0]  # u16
    
    # Следующие 2 байта: u16 (модель пары)
    pair_model = struct.unpack_from('<H', data, 14)[0]  # u16
    
    # Следующий байт: u8 (версия ПО)
    fwr_rel_num = struct.unpack_from('<B', data, 16)[0]  # u8
    
    # Последний байт: флаги
    const_flags = struct.unpack_from('<B', data, 17)[0]  # u8
    
    # Разбираем биты флагов
    leftright = (const_flags >> 0) & 0x01
    asa_enabled = (const_flags >> 1) & 0x01
    binaural_enabled = (const_flags >> 2) & 0x01
    battery_type = (const_flags >> 3) & 0x01
    
    # Формируем результат
    result = {
        'Основные параметры громкости': {
            'VOLUME_MIN': f'{volume_min}',
            'VOLUME_MID': f'{volume_mid}',
            'VOLUME_MAX': f'{volume_max}',
            'VOLUME_STEP': f'{volume_step}'
        },
        'Серийные номера': {
            'SERIAL_NUM': f'{serial_num} (0x{serial_num:08X})',
            'PAIR_SERIAL_NUM': f'{pair_serial_num} (0x{pair_serial_num:08X})'
        },
        'Модели устройств': {
            'MODEL': f'{model} (0x{model:04X})',
            'PAIR_MODEL': f'{pair_model} (0x{pair_model:04X})'
        },
        'Версия ПО': {
            'FWR_REL_NUM': f'{fwr_rel_num}'
        },
        'Флаги (CONST_FLAGS)': {
            'LEFTRIGHT': f'{leftright} ({"Right" if leftright else "Left"})',
            'ASA_ENABLED': f'{asa_enabled} ({"Enabled" if asa_enabled else "Disabled"})',
            'BINAURAL_ENABLED': f'{binaural_enabled} ({"Enabled" if binaural_enabled else "Disabled"})',
            'BATTERY_TYPE': f'{battery_type} ({"Rechargeable" if battery_type else "Battery"})'
        },
        'Сырые данные': {
            'Hex': hex_string.upper(),
            'Bytes': ' '.join(f'{b:02X}' for b in data)
        }
    }
    
    return result

def print_result(result):
    """Красиво выводит результат"""
    print("\n" + "="*60)
    print("РАСШИФРОВКА ХАРАКТЕРИСТИКИ IAI_CONST")
    print("="*60)
    
    for category, values in result.items():
        if category == 'Сырые данные':
            continue  # Выведем в конце
        
        print(f"\n{category}:")
        print("-" * 40)
        for key, value in values.items():
            print(f"  {key:<20} : {value}")
    
    print("\n" + "="*60)
    print("Сырые данные:")
    print("-" * 40)
    for key, value in result['Сырые данные'].items():
        print(f"  {key:<20} : {value}")
    print("="*60)

def main():
    print("Парсер характеристики BLE устройства IAI_CONST")
    print("Формат: 18 байт в hex (36 символов)")
    print("Пример: FA000601F3EE0B00F0EE0B00890089000104")
    print("-" * 60)
    
    while True:
        try:
            # Запрашиваем ввод
            hex_input = input("\nВведите значение характеристики (или 'q' для выхода): ").strip()
            
            if hex_input.lower() in ['q', 'quit', 'exit']:
                print("Выход из программы.")
                break
            
            if not hex_input:
                continue
            
            # Парсим и выводим результат
            result = parse_iai_const_value(hex_input)
            print_result(result)
            
        except ValueError as e:
            print(f"Ошибка: {e}")
            print("Пожалуйста, проверьте формат данных.")
        except KeyboardInterrupt:
            print("\n\nПрограмма прервана пользователем.")
            break
        except Exception as e:
            print(f"Неожиданная ошибка: {e}")
            if input("Показать подробности? (y/n): ").lower() == 'y':
                import traceback
                traceback.print_exc()

if __name__ == "__main__":
    main()


""" Особенности скрипта парсинга IAI_CONST:
1. Проверка формата: Проверяет длину и корректность hex-строки

2. Обработка ошибок: Предусмотрена обработка некорректного ввода

3. Удобный интерфейс: Подробные подсказки и структурированный вывод

4. Поддержка little-endian: Правильно интерпретирует многобайтовые значения

5. Интерактивный режим: Можно вводить несколько значений подряд

6. Выход по команде: Введите 'q', 'quit' или 'exit' для выхода

Скрипт автоматически:

- Убирает префиксы 0x и пробелы

- Проверяет длину данных (должно быть 36 hex-символов)

- Преобразует hex в байты

- Распаковывает структуру согласно документации

- Интерпретирует битовые флаги

- Выводит значения в десятичном и hex-формате """