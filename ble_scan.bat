@echo off
setlocal

REM Активируем виртуальное окружение
call venv\Scripts\activate.bat

REM Переходим в папку src
cd src

REM Запускаем сканирование BLE устройств
python ble_scan.py

REM Ждем нажатия клавиши, чтобы окно не закрылось само
pause