# KeePassFIDO2 - Native Windows WebAuthn Plugin

Плагин KeePass Key Provider, который позволяет разблокировать базу данных KeePass с помощью FIDO2 аутентификатора (аппаратный ключ, Android-телефон или Windows Hello), используя нативный Windows WebAuthn API.

## 🎯 Основные преимущества нового подхода

### Было (старая версия):
- ❌ Отдельное C++ приложение для взаимодействия с FIDO2
- ❌ Запуск с повышенными правами (UAC prompt)
- ❌ Хранение ключа в поле "icon" credential (костыль)
- ❌ Требование создания двух credentials
- ❌ Зависимость от libfido2

### Стало (новая версия):
- ✅ Нативный Windows WebAuthn API (встроен в Windows 10 22H2+ / Windows 11)
- ✅ Без требования повышенных прав
- ✅ Использование стандартного механизма **hmac-secret** extension
- ✅ Один credential на базу данных
- ✅ Чистая архитектура, соответствующая стандартам FIDO2
- ✅ Только C# код, без внешних зависимостей

## 📋 Требования

- **Windows 10 22H2** или **Windows 11** (WebAuthn API v4+)
- **KeePass 2.x**
- **Аутентификатор** с поддержкой hmac-secret/PRF — один из:
  - аппаратный FIDO2-ключ (YubiKey 5, SoloKey, Nitrokey 3, Google Titan и др.)
  - **Android-телефон** (Android 14+, Google Password Manager) — по QR-коду через hybrid-транспорт (Windows 11 23H2+)
  - **Windows Hello** — требуется Windows 11 24H2/25H2 с обновлением KB5077181 (build ≥ 26100.7840 / 26200.7840, февраль 2026)

## 🔧 Установка

1. Скопируйте `KeePassFIDO2.dll` в папку Plugins вашего KeePass
2. Перезапустите KeePass
3. Плагин появится в списке Key Providers

## 📖 Использование

### Создание новой базы данных с FIDO2

1. Создайте новую базу данных через `Файл` → `Создать`
2. В диалоге выбора мастер-ключа нажмите `Key file / provider`
3. Выберите `FIDO2 Key Provider (Windows WebAuthn)`
4. В системном диалоге Windows выберите аутентификатор:
   - **FIDO2 ключ** — введите PIN и нажмите кнопку на ключе
   - **Телефон** — отсканируйте QR-код и подтвердите на Android
   - **Windows Hello** — подтвердите PIN/биометрией
5. Рядом с базой данных будет создан файл `.fido2` с credential ID (в диалогах аутентификатора credential подписан именем базы: `KeePass: <имя>.kdbx`)
6. **ВАЖНО:** Сохраните файл `.fido2` вместе с базой данных!

### Открытие базы данных с FIDO2

1. Откройте базу данных через `Файл` → `Открыть`
2. В диалоге выбора мастер-ключа нажмите `Key file / provider`
3. Выберите `FIDO2 Key Provider (Windows WebAuthn)`
4. Подтвердите аутентификацию тем же аутентификатором, которым создавался credential
5. База данных будет разблокирована

### Управление Credentials

1. Откройте `Tools` → `KeePassFIDO2`
2. В открывшемся окне вы увидите:
   - Версию Windows WebAuthn API
   - Статус credential для текущей базы данных
   - Кнопку управления credential (удаление)
   - Кнопку **Диагностика** — лог вызовов WebAuthn, тест создания credential и получения PRF-секрета с проверкой детерминированности

## 🔐 Как это работает

### hmac-secret Extension

Плагин использует стандартный FIDO2 механизм `hmac-secret` extension:

1. При создании credential запрашивается `hmac-secret` extension и `bEnablePrf`; на WebAuthn API v8+ передаётся `pPRFGlobalEval`, и секрет возвращается сразу в attestation (второй диалог не нужен)
2. Credential ID сохраняется в файл `.fido2` рядом с базой данных
3. При разблокировке:
   - Плагин загружает credential ID из файла
   - Отправляет GetAssertion с фиксированной солью через `pHmacSecretSaltValues`; Windows применяет PRF-преобразование `SHA-256("WebAuthn PRF" || 0x00 || salt)`
   - Аутентификатор вычисляет HMAC-SHA256 от соли с использованием секретного ключа
   - Результат (32 байта) используется как мастер-ключ для KeePass напрямую

### Преимущества hmac-secret

- **Детерминированность:** Один и тот же credential всегда генерирует один и тот же ключ для одной соли
- **Криптографическая стойкость:** 32-байтовый HMAC-SHA256
- **Стандартность:** Официальный FIDO2 extension (не требует костылей)
- **Безопасность:** Секретный ключ никогда не покидает аутентификатор

## 🏗️ Архитектура

```
KeePassFIDO2.dll
├── FIDO2KeyProvider.cs          - Key Provider для KeePass
├── WebAuthn/
│   ├── WebAuthnApi.cs           - P/Invoke обертки для webauthn.dll
│   ├── WebAuthnHelper.cs        - Высокоуровневый API для работы с WebAuthn
│   └── CredentialStorage.cs     - Сохранение/загрузка credential ID
├── FIDO2OptionsForm.cs          - Форма настроек плагина
├── FIDO2DiagnosticsForm.cs      - Диагностика (лог WebAuthn, тест PRF)
└── KeePassFIDO2Ext.cs           - Точка входа плагина
```

## ⚠️ Важные замечания

1. **Файл .fido2 критически важен!** Без него вы не сможете открыть базу данных. Храните его вместе с базой данных.

2. **Резервные копии:** Рекомендуется настроить дополнительный способ доступа к базе данных (например, пароль) на случай потери FIDO2 ключа.

3. **Один credential = одна база данных:** Каждая база данных использует свой уникальный credential.

4. **Совместимость аутентификаторов:** аппаратный ключ должен поддерживать `hmac-secret`; телефон — PRF (Google Password Manager, Android 14+; Samsung Pass и др. не поддерживают); Windows Hello — только с KB5077181 (build ≥ 26100.7840 / 26200.7840). Проверить можно через `Tools → KeePassFIDO2 → Диагностика`.

5. **Не меняйте RP ID и соль** (`WebAuthnHelper.RP_ID`, `PRF_SALT`) — от них зависит выводимый ключ; изменение сделает все существующие базы неоткрываемыми.

## 🔄 Миграция со старой версии

Если вы использовали старую версию плагина (с C++ DeviceCommunicator):

1. **Старые credentials не совместимы с новой версией!**
2. Создайте новую базу данных с новым подходом
3. Перенесите данные из старой базы в новую
4. Удалите старые credentials с аутентификатора через приложение производителя

## 🐛 Устранение неполадок

### "Windows WebAuthn API недоступен"
- Требуется WebAuthn API v4+: Windows 10 22H2 или Windows 11
- Проверьте наличие файла `C:\Windows\System32\webauthn.dll`

### "Файл с FIDO2 credential не найден"
- Убедитесь, что файл `.fido2` находится в той же папке, что и база данных
- Проверьте, что имя файла совпадает с именем базы данных (только расширение .fido2)

### "Аутентификатор не поддерживает hmac-secret/PRF" при создании
- Аппаратный ключ без hmac-secret (старые U2F-ключи) — используйте FIDO2-ключ (YubiKey 5 и новее)
- Windows Hello на сборке без KB5077181 — обновите Windows 11 до build ≥ 26100.7840 / 26200.7840
- Телефон с менеджером паролей без PRF — используйте Google Password Manager

### "hmac-secret not returned by authenticator" при открытии
- Credential создавался другим аутентификатором или был удалён с него
- В диагностике смотрите строки `bPrfEnabled`, `pHmacSecret` и `Секрет совпадает`

## 📚 Технические детали

### Windows WebAuthn API
- Документация: https://docs.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis
- DLL: `webauthn.dll` (встроена в Windows), заголовок: https://github.com/microsoft/webauthn/blob/master/webauthn.h
- Минимальная версия API: 4 (`pHmacSecretSaltValues`, `pHmacSecret`); API 8+ — `pPRFGlobalEval` (секрет при создании, нужен для Windows Hello)

### FIDO2 hmac-secret Extension
- Спецификация: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-hmac-secret-extension
- Алгоритм: HMAC-SHA256, соль передаётся с PRF-преобразованием (WebAuthn PRF extension)
- Размер ключа: 32 байта

## 📝 Лицензия

Этот проект был переработан для использования нативного Windows WebAuthn API вместо внешнего C++ приложения и библиотеки libfido2.


## 🤝 Вклад

Вопросы, предложения и pull requests приветствуются!

## ⚡ Производительность

- Время разблокировки: ~2-3 секунды (ключ / Windows Hello), ~10-20 секунд для телефона по QR
- Без сетевых запросов
- Без дополнительных процессов
- Минимальное потребление памяти
