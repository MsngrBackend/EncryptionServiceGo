# EncryptionService

Легкий Go-сервис для end-to-end шифрования сообщений в Msngr.

Сервис хранит публичные X25519-ключи пользователей и формирует зашифрованные конверты сообщений в формате `nacl-box-x25519-xsalsa20-poly1305-sealed-v1`. Приватные ключи не должны попадать в EncryptionService или MessageServiceGo: клиент генерирует пару ключей локально, регистрирует только публичный ключ и отправляет в MessageServiceGo уже зашифрованный `content`.

## Запуск

```powershell
Copy-Item .env.example .env
docker compose up --build -d
```

HTTP endpoint:

```text
http://localhost:8081
```

Проверка:

```http
GET /health
```

## Переменные окружения

| Переменная | Значение по умолчанию | Назначение |
|---|---|---|
| `DATABASE_URL` | `postgres://postgres:ultramegasecret@localhost:5432/messaging_db` | Подключение к PostgreSQL |
| `ENCRYPTION_SERVICE_ADDR` | `:8081` | HTTP-адрес сервиса |

## API

### Зарегистрировать публичный ключ

`public_key` — base64 от 32 байт X25519 public key.

```http
POST /keys/
Content-Type: application/json
```

```json
{"user_id":"user1","public_key":"base64-encoded-32-byte-key"}
```

### Получить публичный ключ

```http
GET /keys/{user_id}/
```

### Получить ключи нескольких пользователей

```http
POST /keys/lookup/
Content-Type: application/json
```

```json
{"user_ids":["user1","user2"]}
```

### Зашифровать сообщение

Endpoint может использовать публичные ключи из хранилища или ключи, переданные прямо в `recipients`.

```http
POST /messages/encrypt/
Content-Type: application/json
```

```json
{
  "content": "hello",
  "recipients": [
    {"user_id": "user1"},
    {"user_id": "user2", "public_key": "base64-encoded-32-byte-key"}
  ]
}
```

Ответ:

```json
{
  "version": "nacl-box-x25519-xsalsa20-poly1305-sealed-v1",
  "envelopes": [
    {
      "user_id": "user1",
      "algorithm": "nacl-box-x25519-xsalsa20-poly1305-sealed-v1",
      "ciphertext": "base64-ciphertext"
    }
  ]
}
```

## MessageServiceGo

`MessageServiceGo` остается транспортом и хранилищем: в `messages.content` можно сохранять JSON с `version` и `envelopes` как строку. MessageServiceGo не расшифровывает payload.