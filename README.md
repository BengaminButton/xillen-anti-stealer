# XILLEN Anti-Stealer

## Описание
Мощный инструмент для обнаружения и мониторинга стилеров, кейлоггеров и других вредоносных программ, которые крадут конфиденциальные данные.

## Возможности
- Обнаружение подозрительных процессов
- Сканирование окон на наличие вредоносных заголовков
- Проверка реестра на предмет персистентности
- Анализ файловой системы
- Мониторинг сетевых соединений
- Непрерывное наблюдение за системой
- Генерация отчетов

## Установка
```bash
git clone https://github.com/BengaminButton/xillen-anti-stealer
cd xillen-anti-stealer
make
```

## Использование
```bash
# Запуск программы
./xillen_anti_stealer.exe

# Сборка из исходного кода
make clean
make
```

## Функции
1. **Сканирование системы** - Полная проверка на наличие угроз
2. **Запуск мониторинга** - Непрерывное наблюдение
3. **Остановка мониторинга** - Прекращение наблюдения
4. **Сохранение отчета** - Экспорт результатов в файл

## Обнаруживаемые угрозы
- Стилеры (stealer.exe, keylogger.exe)
- RAT программы (rat.exe, backdoor.exe)
- Вредоносные DLL (hook.dll, inject.dll)
- Автоматизированные инструменты (ahk.exe, macro.exe)
- Подозрительные процессы записи (recorder.exe)

## Подозрительные порты
- 4444, 8080, 1337 - Стандартные порты RAT
- 6667-6669 - IRC ботнеты
- 7000-7002, 8000-8002, 9000-9002 - Альтернативные порты

## Требования
- Windows 7/8/10/11
- Visual Studio 2019+ или MinGW-w64
- C++17 совместимый компилятор

## Сборка
```bash
# MinGW-w64
g++ -std=c++17 -Wall -Wextra -O2 -o xillen_anti_stealer.exe anti_stealer.cpp -lws2_32 -liphlpapi -lpsapi

# Visual Studio
cl /EHsc /std:c++17 anti_stealer.cpp ws2_32.lib iphlpapi.lib psapi.lib
```

## Авторы
- **@Bengamin_Button** - Основной разработчик
- **@XillenAdapter** - Технический консультант

## Ссылки
- Веб-сайт: https://benjaminbutton.ru/
- XILLEN: https://xillenkillers.ru/
- Telegram: t.me/XillenAdapter
