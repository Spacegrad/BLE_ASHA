import struct
import sys

def parse_iai_const_value(hex_string):
    """Парсит значение характеристики IAI_CONST (18 байт)"""
    
    # Убираем возможные префиксы и пробелы
    hex_string = hex_string.strip().replace('0x', '').replace(' ', '')
    
    # Проверяем длину
    if len(hex_string) != 36:  # 18 байт * 2 символа
        raise ValueError(f"IAI_CONST: ожидается 36 hex-символов (18 байт), получено {len(hex_string)}")
    
    # Преобразуем в байты
    try:
        data = bytes.fromhex(hex_string)
    except ValueError:
        raise ValueError("Некорректный hex-формат")
    
    if len(data) != 18:
        raise ValueError(f"IAI_CONST: ожидается 18 байт, получено {len(data)}")
    
    # Распаковываем структуру (little-endian)
    volume_min = struct.unpack_from('<b', data, 0)[0]  # i8
    volume_mid = struct.unpack_from('<b', data, 1)[0]  # i8
    volume_max = struct.unpack_from('<b', data, 2)[0]  # i8
    volume_step = struct.unpack_from('<B', data, 3)[0]  # u8
    
    serial_num = struct.unpack_from('<I', data, 4)[0]  # u32
    pair_serial_num = struct.unpack_from('<I', data, 8)[0]  # u32
    model = struct.unpack_from('<H', data, 12)[0]  # u16
    pair_model = struct.unpack_from('<H', data, 14)[0]  # u16
    fwr_rel_num = struct.unpack_from('<B', data, 16)[0]  # u8
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
        }
    }
    
    return result

def parse_iai_vars_value(hex_string):
    """Парсит значение характеристики IAI_VARS (9 байт)"""
    
    # Убираем возможные префиксы и пробелы
    hex_string = hex_string.strip().replace('0x', '').replace(' ', '')
    
    # Проверяем длину
    if len(hex_string) != 18:  # 9 байт * 2 символа
        raise ValueError(f"IAI_VARS: ожидается 18 hex-символов (9 байт), получено {len(hex_string)}")
    
    # Преобразуем в байты
    try:
        data = bytes.fromhex(hex_string)
    except ValueError:
        raise ValueError("Некорректный hex-формат")
    
    if len(data) != 9:
        raise ValueError(f"IAI_VARS: ожидается 9 байт, получено {len(data)}")
    
    # Распаковываем структуру
    uptime = struct.unpack_from('<B', data, 0)[0]  # u8
    volume = struct.unpack_from('<B', data, 1)[0]  # u8
    prog = struct.unpack_from('<B', data, 2)[0]  # u8
    asa_val = struct.unpack_from('<B', data, 3)[0]  # u8
    tone = struct.unpack_from('<B', data, 4)[0]  # u8
    tone_hi = struct.unpack_from('<B', data, 5)[0]  # u8
    beamformer = struct.unpack_from('<B', data, 6)[0]  # u8
    nr_type = struct.unpack_from('<B', data, 7)[0]  # u8
    var_flags = struct.unpack_from('<B', data, 8)[0]  # u8
    
    # Разбираем биты флагов
    ivolume = (var_flags >> 0) & 0x01
    volume_lim = (var_flags >> 1) & 0x01
    handshake = (var_flags >> 2) & 0x01
    prog_flag = (var_flags >> 3) & 0x01
    asa_flag = (var_flags >> 4) & 0x01
    muted = (var_flags >> 5) & 0x01
    tc = (var_flags >> 6) & 0x01
    led_free = (var_flags >> 7) & 0x01
    
    # Проверяем маскированные значения (0xFF)
    tone_str = f'{tone}' if tone != 0xFF else f'{tone} (Masked/Not changing)'
    tone_hi_str = f'{tone_hi}' if tone_hi != 0xFF else f'{tone_hi} (Masked/Not changing)'
    beamformer_str = f'{beamformer}' if beamformer != 0xFF else f'{beamformer} (Masked/Not changing)'
    nr_type_str = f'{nr_type}' if nr_type != 0xFF else f'{nr_type} (Masked/Not changing)'
    
    # Определяем специальные значения
    prog_name = f'{prog}'
    if prog == 0x06:
        prog_name += ' (ASA/Autophone)'
    
    nr_type_desc = f'{nr_type}'
    if nr_type != 0xFF:
        if nr_type == 0:
            nr_type_desc += ' (Off)'
        elif 1 <= nr_type <= 4:
            nr_type_desc += f' (Level {nr_type})'
    
    # Формируем результат
    result = {
        'Состояние устройства': {
            'UPTIME': f'{uptime} сек',
            'VOLUME': f'{volume} шагов (VOLUME_STEP)',
            'PROG': prog_name,
            'ASA': f'{asa_val}'
        },
        'Настройки звука': {
            'TONE': tone_str + ' [0-100, 50=нейтр.]',
            'TONE_HI': tone_hi_str + ' [0-100, 50=нейтр.]',
            'BEAMFORMER': beamformer_str,
            'NR_TYPE': nr_type_desc
        },
        'Флаги (VAR_FLAGS)': {
            'IVOLUME': f'{ivolume} ({"Independent" if ivolume else "Sync"})',
            'VOLUME_LIM': f'{volume_lim} ({"Forced" if volume_lim else "Normal"})',
            'HANDSHAKE': f'{handshake} ({"Paired" if handshake else "Not paired"})',
            'PROG': f'{prog_flag} ({"Use PROG field" if prog_flag else "Ignore"})',
            'ASA': f'{asa_flag} ({"Update predictor" if asa_flag else "No update"})',
            'MUTED': f'{muted} ({"Muted" if muted else "Normal"})',
            'TC': f'{tc} ({"Coil active" if tc else "Inactive"})',
            'LED_FREE': f'{led_free} (TODO)'
        }
    }
    
    return result

def parse_iai_progs_value(hex_string):
    """Парсит значение характеристики IAI_PROGS (17 байт)"""
    
    # Убираем возможные префиксы и пробелы
    hex_string = hex_string.strip().replace('0x', '').replace(' ', '')
    
    # Проверяем длину
    if len(hex_string) != 34:  # 17 байт * 2 символа
        raise ValueError(f"IAI_PROGS: ожидается 34 hex-символа (17 байт), получено {len(hex_string)}")
    
    # Преобразуем в байты
    try:
        data = bytes.fromhex(hex_string)
    except ValueError:
        raise ValueError("Некорректный hex-формат")
    
    if len(data) != 17:
        raise ValueError(f"IAI_PROGS: ожидается 17 байт, получено {len(data)}")
    
    # Распаковываем структуру
    prog0 = struct.unpack_from('<B', data, 0)[0]  # u8
    prog1 = struct.unpack_from('<B', data, 1)[0]  # u8
    prog2 = struct.unpack_from('<B', data, 2)[0]  # u8
    prog3 = struct.unpack_from('<B', data, 3)[0]  # u8
    prog4 = struct.unpack_from('<B', data, 4)[0]  # u8
    prog5 = struct.unpack_from('<B', data, 5)[0]  # u8
    prog6 = struct.unpack_from('<B', data, 16)[0]  # u8
    
    # Преобразуем ASCII-коды в символы для имен программ
    def byte_to_char(b):
        if 32 <= b <= 126:  # Печатные ASCII символы
            return chr(b)
        else:
            return f'[0x{b:02X}]'
    
    prog0_char = byte_to_char(prog0)
    prog1_char = byte_to_char(prog1)
    prog2_char = byte_to_char(prog2)
    prog3_char = byte_to_char(prog3)
    prog4_char = byte_to_char(prog4)
    prog5_char = byte_to_char(prog5)
    prog6_char = byte_to_char(prog6)
    
    # Формируем результат
    result = {
        'Названия программ': {
            'PROG0 (Слот 0)': f'{prog0} = {prog0_char}',
            'PROG1 (Слот 1)': f'{prog1} = {prog1_char}',
            'PROG2 (Слот 2)': f'{prog2} = {prog2_char}',
            'PROG3 (Слот 3)': f'{prog3} = {prog3_char}',
            'PROG4 (Слот 4)': f'{prog4} = {prog4_char}',
            'PROG5 (Слот 5)': f'{prog5} = {prog5_char}'
        },
        'Автофон': {
            'PROG6 (Autophone)': f'{prog6} = {prog6_char}'
        },
        'Зарезервированные байты': {
            'RSRVD0-RSRVD9': ' '.join(f'{b:02X}' for b in data[6:16])
        }
    }
    
    return result

def print_result(result, char_type, hex_string):
    """Красиво выводит результат"""
    
    title = {
        'const': 'РАСШИФРОВКА ХАРАКТЕРИСТИКИ IAI_CONST',
        'vars': 'РАСШИФРОВКА ХАРАКТЕРИСТИКИ IAI_VARS',
        'progs': 'РАСШИФРОВКА ХАРАКТЕРИСТИКИ IAI_PROGS'
    }[char_type]
    
    print("\n" + "="*70)
    print(title)
    print("="*70)
    print(f"Исходное значение: 0x{hex_string.upper()}")
    print("-" * 70)
    
    for category, values in result.items():
        print(f"\n{category}:")
        print("-" * 40)
        for key, value in values.items():
            print(f"  {key:<25} : {value}")

def main():
    print("Парсер характеристик BLE устройства IAI")
    print("="*70)
    print("Поддерживаемые характеристики:")
    print("  1. IAI_CONST - постоянные параметры (18 байт)")
    print("  2. IAI_VARS - переменные параметры (9 байт)")
    print("  3. IAI_PROGS - названия программ (17 байт)")
    print("="*70)
    print("Примеры значений:")
    print("  IAI_CONST: FA000601F3EE0B00F0EE0B00890089000104")
    print("  IAI_VARS:  000600003232000080")
    print("  IAI_PROGS: 0001021213FFFFFFFFFFFFFFFFFFFFFF08")
    print("="*70)
    
    while True:
        try:
            print("\nВыберите тип характеристики:")
            print("  1 - IAI_CONST (18 байт)")
            print("  2 - IAI_VARS (9 байт)")
            print("  3 - IAI_PROGS (17 байт)")
            print("  q - Выход")
            
            choice = input("\nВаш выбор (1-3 или q): ").strip().lower()
            
            if choice in ['q', 'quit', 'exit']:
                print("Выход из программы.")
                break
            
            if choice not in ['1', '2', '3']:
                print("Неверный выбор. Попробуйте снова.")
                continue
            
            # Запрашиваем значение
            if choice == '1':
                prompt = "Введите значение IAI_CONST (36 hex-символов): "
                parser = parse_iai_const_value
                char_type = 'const'
            elif choice == '2':
                prompt = "Введите значение IAI_VARS (18 hex-символов): "
                parser = parse_iai_vars_value
                char_type = 'vars'
            else:  # choice == '3'
                prompt = "Введите значение IAI_PROGS (34 hex-символа): "
                parser = parse_iai_progs_value
                char_type = 'progs'
            
            hex_input = input(prompt).strip()
            
            if not hex_input:
                continue
            
            # Парсим и выводим результат
            result = parser(hex_input)
            print_result(result, char_type, hex_input.replace('0x', '').replace(' ', ''))
            
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
1. Поддержка трех характеристик:
    - IAI_CONST - постоянные параметры (18 байт)
    - IAI_VARS - переменные параметры (9 байт)
    - IAI_PROGS - названия программ (17 байт)

2. Улучшенный парсинг IAI_VARS:
    - Обработка маскированных значений (0xFF = не изменять)
    - Интерпретация специальных значений (PROG=0x06 = ASA/Автофон)
    - Детальное описание NR_TYPE (0=выкл, 1-4=уровни подавления)
    - Правильное отображение диапазонов TONE и TONE_HI

3. Парсинг IAI_PROGS:
    - Преобразование ASCII-кодов в символы
    - Отображение зарезервированных байтов
    - Отдельный вывод для автофона (PROG6)

4. Улучшенный интерфейс:
    - Меню выбора типа характеристики
    - Разные подсказки для каждого типа
    - Примеры значений для тестирования 
    
Особенности обработки:
1. IAI_VARS:

    - Значения 0xFF помечаются как "Masked/Not changing"
    - PROG=0x06 отображается как "ASA/Autophone"
    - NR_TYPE получает текстовое описание

2. IAI_PROGS:

    - ASCII-коды преобразуются в символы (если это печатные символы)
    - Непечатные символы отображаются в hex-формате
    - Зарезервированные байты выводятся как hex

3. Обработка ошибок:

    - Проверка длины для каждого типа
    - Валидация hex-формата
    - Четкие сообщения об ошибках     """

