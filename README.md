# Webhook Logger API

Serverless микросервис для приема, валидации HMAC подписей и асинхронного логирования вебхуков, построенный на базе Yandex Cloud.

> Проект выполнен в рамках тестового задания: [TASK.md](TASK.md)

## 📋 Описание задачи

Проект реализует надежную систему обработки вебхуков от внешних сервисов (например, GitHub, Stripe). Система спроектирована так, чтобы быстро отвечать отправителю (чтобы избежать таймаутов) и гарантированно сохранять данные даже при высокой нагрузке.

**Ключевые особенности:**
*   ✅ **Быстрый ответ**: `webhook-receiver` отвечает < 200ms, так как тяжелая обработка вынесена в фон.
*   ✅ **Безопасность**: Проверка HMAC-SHA256 подписи для защиты от поддельных запросов.
*   ✅ **Надежность**: Использование очереди YMQ (Standard Queue) гарантирует доставку сообщений.
*   ✅ **Масштабируемость**: Обработка батчами с помощью Serverless Containers и YDB.
*   ✅ **История событий**: Отдельный API для просмотра логов.

## ⚡ Оптимизация производительности (Latency < 200ms)

Для достижения минимального времени ответа (`webhook-receiver`) были применены следующие оптимизации:

1.  **Память функции (512MB)**:
    *   Увеличение памяти Cloud Function с 128MB до 512MB.
    *   *Почему:* В Yandex Cloud Functions мощность CPU пропорциональна выделенной памяти. 128MB недостаточно для быстрого старта Python-интерпретатора и SSL-рукопожатий `boto3`. Увеличение памяти дает линейный прирост скорости CPU.

2.  **Быстрый JSON парсер (`orjson`)**:
    *   Замена стандартной библиотеки `json` на `orjson` (Rust-based).
    *   *Почему:* Вебхуки часто содержат объемные JSON-пейлоады. `orjson` сериализует и парсит JSON в 5-10 раз быстрее стандартного модуля, экономя десятки миллисекунд на каждом запросе.

3.  **Устранение Cold Starts**:
    *   Использование `--provisioned-instances-count 1`.
    *   *Почему:* "Холодный старт" функции (поднятие контейнера) занимает 1-3 секунды. Зарезервированный инстанс держит одну копию функции всегда "горячей" и готовой к обработке запроса, гарантируя стабильное время ответа даже при редких запросах.

## 🏗 Архитектура

Решение использует паттерн **Fan-in / Async Processing**:

```
External Service (GitHub/Stripe)
      ↓ POST /webhook (с заголовком X-Webhook-Signature)
┌─────────────────────────────────────────────────────┐
│ 1. webhook-receiver (Cloud Function)                │
│    - Валидация HMAC подписи (ключ в Lockbox)        │
│    - Отправка в YMQ                                 │
│    - Ответ 200 OK                                   │
└─────────────────────────────────────────────────────┘
      ↓
┌─────────────────────────────────────────────────────┐
│ 2. YMQ Standard Queue (webhook-events)              │
│    - Буферизация сообщений                          │
└─────────────────────────────────────────────────────┘
      ↓ (YMQ Trigger собирает батчи)
┌─────────────────────────────────────────────────────┐
│ 3. webhook-processor (Serverless Container)         │
│    - Парсинг сообщений                              │
│    - Сохранение в YDB                               │
└─────────────────────────────────────────────────────┘
      ↓
┌─────────────────────────────────────────────────────┐
│ 4. YDB Serverless (Таблица webhook_logs)            │
└─────────────────────────────────────────────────────┘
```

## 🛠 Компоненты системы

1.  **webhook-receiver** (Cloud Function): Точка входа. Проверяет подпись, генерирует `log_id`, отправляет событие в очередь.
2.  **webhook-events** (YMQ): Очередь сообщений со временем видимости 5 минут и хранением 24 часа.
3.  **webhook-processor** (Serverless Container): Python приложение (FastAPI), запускаемое триггером. Разбирает пачки сообщений и пишет в БД.
4.  **logs-api** (Cloud Function): HTTP API для запроса истории событий из YDB.
5.  **YDB** (Serverless): База данных для хранения логов.
6.  **Lockbox**: Хранилище секретов (SECRET_KEY) для валидации подписей.

## 🚀 Установка и Деплой

### Предварительные требования
*   Аккаунт в Yandex Cloud
*   Установленный [YC CLI](https://cloud.yandex.ru/docs/cli/quickstart)
*   Установленный Docker
*   Python 3.12+
*   Установленный [YDB CLI](https://ydb.tech/docs/ru/reference/ydb-cli/install) (для создания таблиц)
    ```bash
    curl https://storage.yandexcloud.net/yandexcloud-ydb/install.sh | bash
    ```
*   Установленный [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) (для работы с YMQ)
    ```bash
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    sudo ./aws/install
    ```

### Шаг 1: Настройка окружения и прав доступа

Инициализируйте CLI и создайте сервисный аккаунт:

```bash
# Инициализация
yc init

# Создание сервисного аккаунта
yc iam service-account create --name webhook-logger-sa

# Получение ID аккаунта
SA_ID=$(yc iam service-account get webhook-logger-sa --format json | jq -r '.id')

# Назначение ролей
yc resource-manager folder add-access-binding <FOLDER_ID> --role ymq.writer --subject serviceAccount:$SA_ID
yc resource-manager folder add-access-binding <FOLDER_ID> --role ymq.reader --subject serviceAccount:$SA_ID
yc resource-manager folder add-access-binding <FOLDER_ID> --role ydb.editor --subject serviceAccount:$SA_ID
yc resource-manager folder add-access-binding <FOLDER_ID> --role lockbox.payloadViewer --subject serviceAccount:$SA_ID
yc resource-manager folder add-access-binding <FOLDER_ID> --role serverless.containers.invoker --subject serviceAccount:$SA_ID

# Создание статических ключей для YMQ (сохраните вывод!)
yc iam access-key create --service-account-name webhook-logger-sa
```

### Шаг 2: База данных YDB

1.  Создайте базу данных Serverless:
    ```bash
    yc ydb database create --name webhook-logger-db --serverless
    ```
    *Сохраните Endpoint (например, `grpcs://ydb.serverless.yandexcloud.net:2135`) и Database path (например, `/ru-central1/...`).*

2.  Создайте таблицу `webhook_logs`:
    ```bash
    # Замените <YDB_ENDPOINT> и <YDB_DATABASE> на ваши значения
    ydb -e <YDB_ENDPOINT> -d <YDB_DATABASE> \
      --yc-token-file <(yc config get token) \
      scripting yql -f ydb_schemas/webhook_logs.sql
    ```

### Шаг 3: Секреты Lockbox

Создайте секрет для HMAC подписи:

```bash
# Генерируем случайный ключ
openssl rand -hex 32

# Создаем секрет в Lockbox
yc lockbox secret create --name webhook-secret-key \
  --payload "[{'key': 'SECRET_KEY', 'text_value': '<ВАШ_СГЕНЕРИРОВАННЫЙ_КЛЮЧ>'}]"
```

### Шаг 4: Очередь YMQ

Создайте стандартную очередь `webhook-events`. Для работы с YMQ используем `aws` CLI (так как API совместимо с SQS).

Сначала настройте aws cli:
```bash
aws configure
# AWS Access Key ID: ID ключа из Шага 1
# AWS Secret Access Key: Секретный ключ из Шага 1
# Default region name: ru-central1
```

Создание очереди:
```bash
aws sqs create-queue \
  --queue-name webhook-events \
  --attributes VisibilityTimeout=300,MessageRetentionPeriod=86400 \
  --endpoint-url https://message-queue.api.cloud.yandex.net
```
*Сохраните URL очереди (QueueUrl).*

### Шаг 5: Деплой webhook-receiver

```bash
cd webhook-receiver
zip function.zip handler.py requirements.txt

yc serverless function create --name webhook-receiver

yc serverless function version create \
  --function-name webhook-receiver \
  --runtime python312 \
  --entrypoint handler.handler \
  --memory 512m \
  --execution-timeout 10s \
  --source-path function.zip \
  --service-account-id $SA_ID \
  --environment YMQ_QUEUE_URL=<YMQ_QUEUE_URL> \
  --environment AWS_ACCESS_KEY_ID=<AWS_ACCESS_KEY_ID> \
  --environment AWS_SECRET_ACCESS_KEY=<AWS_SECRET_ACCESS_KEY> \
  --secret name=webhook-secret-key,key=SECRET_KEY,environment-variable=LOCKBOX_SECRET_KEY

# Сделать публичной
yc serverless function allow-unauthenticated-invoke webhook-receiver

# Настроить Provisioned Instances (устранение Cold Starts)
yc serverless function set-scaling-policy \
  --name webhook-receiver \
  --tag \$latest \
  --provisioned-instances-count 1
```

### Шаг 6: Деплой webhook-processor

1.  Создайте Container Registry и загрузите образ:
    ```bash
    cd webhook-processor
    yc container registry create --name webhook-logger-registry
    yc container registry configure-docker
    docker build -t cr.yandex/<REGISTRY_ID>/webhook-processor:latest .
    docker push cr.yandex/<REGISTRY_ID>/webhook-processor:latest
    ```

2.  Создайте Serverless Container:
    ```bash
    yc serverless container create --name webhook-processor
    
    yc serverless container revision deploy \
      --container-name webhook-processor \
      --image cr.yandex/<REGISTRY_ID>/webhook-processor:latest \
      --cores 1 --memory 512MB --concurrency 4 \
      --service-account-id $SA_ID \
      --environment YDB_ENDPOINT=<YDB_ENDPOINT> \
      --environment YDB_DATABASE=<YDB_DATABASE>
    ```

3.  Создайте триггер для YMQ:
    Перед созданием триггера нам нужно получить ARN очереди.
    ```bash
    # Получить ARN очереди
    aws sqs get-queue-attributes \
      --queue-url <YMQ_QUEUE_URL> \
      --endpoint-url https://message-queue.api.cloud.yandex.net/ \
      --attribute-names QueueArn
    ```

    Создание триггера:
    ```bash
    yc serverless trigger create message-queue \
      --name webhook-processor-trigger \
      --queue-service-account-name webhook-logger-sa \
      --queue <QUEUE_ARN> \
      --invoke-container-name webhook-processor \
      --invoke-container-path /ymq-trigger \
      --invoke-container-service-account-name webhook-logger-sa \
      --batch-size 10 \
      --batch-cutoff 10s
    ```

### Шаг 7: Деплой logs-api

```bash
cd logs-api
zip function.zip handler.py requirements.txt

yc serverless function create --name logs-api

yc serverless function version create \
  --function-name logs-api \
  --runtime python312 \
  --entrypoint handler.handler \
  --memory 256m \
  --execution-timeout 10s \
  --source-path function.zip \
  --service-account-id $SA_ID \
  --environment YDB_ENDPOINT=<YDB_ENDPOINT> \
  --environment YDB_DATABASE=<YDB_DATABASE>

# Сделать публичной
yc serverless function allow-unauthenticated-invoke logs-api
```

## 🧪 Тестирование

В корне проекта есть скрипт `test_webhook.sh` для автоматизированного тестирования всех компонентов.

1.  Настройте переменные окружения:
    ```bash
    export WEBHOOK_URL="https://functions.yandexcloud.net/..."
    export LOGS_API_URL="https://functions.yandexcloud.net/..."
    export SECRET_KEY="<значение_ключа_из_lockbox>"
    ```

2.  Запустите тест:
    ```bash
    ./test_webhook.sh
    ```

Скрипт проверит:
*   ✅ Отправку валидного вебхука (ожидается 200 OK)
*   ✅ Отправку вебхука с неверной подписью (ожидается 401 Unauthorized)
*   ✅ Доставку сообщения через очередь в YDB
*   ✅ Работу API логов

## 📂 Структура репозитория

*   `webhook-receiver/` - Код функции приема вебхуков (Python).
*   `webhook-processor/` - Код обработчика очереди (FastAPI + Docker).
*   `logs-api/` - Код функции просмотра истории.
*   `ydb_schemas/` - SQL схема таблицы.
*   `commands.txt` - История команд CLI, использованных при настройке.

---
**Разработано в рамках тестового задания.**
