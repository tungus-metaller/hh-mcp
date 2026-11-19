# MCP-сервер для API hh.ru

## Регистрация приложения на dev.hh.ru
1. Создайте приложение, в Redirect URI укажите любой ваш HTTPS-адрес (например, https://вашдомен.ru/oauth/hh) — он используется только для ручного получения пользовательского токена.
2. Токен приложения доступен сразу в кабинете («Сгенерировать токен») — его достаточно для поиска вакансий, работодателей и справочников.

## Конфигурация (переменные окружения)
- HH_ACCESS_TOKEN — токен приложения/пользователя hh.ru (не обязателен: публичные методы работают без токена);
- HH_CLIENT_ID, HH_CLIENT_SECRET — для автообновления пары токенов по refresh_token;
- HH_MCP_TOKEN_FILE — файл пары токенов (по умолчанию ~/.hh_mcp/token.json);
  формат: {"access_token": "...", "refresh_token": "...", "expires_at": 1234567890}
  (expires_at можно не указывать — сервер сам дёрнет refresh при 401);
- HH_MCP_AUTH_TOKEN — Bearer-токен для защиты самого MCP-сервера;
- HH_MCP_HOST / HH_MCP_PORT / HH_MCP_USER_AGENT — хост, порт, User-Agent.

## Запуск локально
    pip install -r requirements.txt
    python hh_mcp_server.py
    # сервер слушает http://0.0.0.0:8000/mcp

## Запуск в Docker
    docker build -t hh-mcp .
    docker run -p 8000:8000 -e HH_MCP_AUTH_TOKEN=secret -e HH_ACCESS_TOKEN=app_token hh-mcp

## Подключение в Yandex AI Studio
1. Публичный эндпоинт: сервер должен быть доступен по HTTPS (например, за Nginx с TLS или через Yandex API Gateway).
2. AI Studio -> Agents -> ваш агент -> Tools -> External MCP server:
   - Transport: Streamable HTTP
   - URL: https://<ваш-домен>/mcp
   - Authorization header: Authorization: Bearer <HH_MCP_AUTH_TOKEN>
3. Выберите, какие инструменты отдать агенту (все 18 умещаются в лимит 50).

## Лимиты и правила hh.ru
- не более ~5 запросов/сек (в сервере стоит ограничитель 4 rps + retry на 429);
- поиск вакансий и резюме: глубина выдачи page*per_page <= 2000;
- User-Agent обязателен и должен быть осмысленным;
- база резюме и отклики — только с токеном работодателя; просмотр чужих резюме — с оплаченной подпиской;
- Условия использования API: не перепродавайте данные, не завышайте нагрузку, соблюдайте требования к названию приложения.

## Безопасность
- Не выставляйте сервер без HH_MCP_AUTH_TOKEN в открытый интернет.
- Токены hh.ru храните в файле с ограниченными правами или в Yandex Lockbox (не в git).
- refresh_token одноразовый: после каждого автообновления сервер перезаписывает файл.
