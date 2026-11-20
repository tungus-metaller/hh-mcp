"""
MCP-сервер для API hh.ru — Python, FastMCP, транспорт Streamable HTTP.

Что умеет:
  - поиск вакансий с фильтрами (текст, регион, опыт, занятость, график, зарплата, роль, работодатель);
  - карточка вакансии, похожие вакансии;
  - работодатели: профиль, активные вакансии, поиск компаний;
  - справочники: регионы (с поиском по названию), профессиональные роли (с поиском),
    специализации, отрасли, словари фильтров;
  - авторизованные методы: /me, свои резюме, просмотр резюме, поиск по базе резюме
    (нужен платный доступ работодателя), отклики по вакансии (/negotiations);
  - универсальный GET-проход через allowlist известных публичных путей.

Авторизация (три режима, определяются автоматически):
  1) HH_ACCESS_TOKEN (env) — токен приложения или пользовательский токен из кабинета dev.hh.ru;
  2) файл с парой токенов (см. HH_MCP_TOKEN_FILE) — поддержка auto-refresh по refresh_token;
  3) без токена — анонимный доступ к публичным методам (вакансии, работодатели, справочники).

Запуск:
    pip install -r requirements.txt
    python hh_mcp_server.py                 # http://0.0.0.0:8000/mcp
    HH_MCP_AUTH_TOKEN=secret python hh_mcp_server.py   # + проверка Bearer на входе

Подключение в Yandex AI Studio:
    Внешний MCP-сервер -> Transport: Streamable HTTP
    URL: http(s)://<ваш-хост>:8000/mcp
    Авторизация: Authorization: Bearer <HH_MCP_AUTH_TOKEN> (если задан)
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastmcp import FastMCP

# ----------------------------------------------------------------------------
# Конфигурация
# ----------------------------------------------------------------------------

BASE_URL = "https://api.hh.ru"

HOST = os.environ.get("HH_MCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))
PATH = "/mcp"

# Токен для защиты самого MCP-сервера (Bearer от клиентов, например AI Studio)
MCP_AUTH_TOKEN = os.environ.get("HH_MCP_AUTH_TOKEN", "")

# Токен приложения/пользователя hh.ru (опционально)
ENV_TOKEN = os.environ.get("HH_ACCESS_TOKEN", "")
TOKEN_FILE = Path(os.environ.get("HH_MCP_TOKEN_FILE", Path.home() / ".hh_mcp" / "token.json"))

# hh.ru требует осмысленный User-Agent (по нему приходит обратная связь о лимитах)
USER_AGENT = os.environ.get(
    "HH_MCP_USER_AGENT",
    "HH-MCP-Server/1.0 (mcp-server; contact@example.com)",
)

# Ограничение hh.ru ~5 запросов/сек; держим безопасные 4 + retry на 429
RATE_INTERVAL = float(os.environ.get("HH_MCP_RATE_INTERVAL", "0.25"))

# Максимальный размер ответа инструмента (символы) — чтобы не раздувать контекст модели
RESP_LIMIT = int(os.environ.get("HH_MCP_RESP_LIMIT", "16000"))

# Пагинация hh.ru: page * per_page <= 2000 (при per_page=100 это максимум 20 страниц)
MAX_PAGE_DEPTH = 2000

# ----------------------------------------------------------------------------
# Внутренние механизмы: токены, rate-limit, HTTP-клиент
# ----------------------------------------------------------------------------

_token_lock = asyncio.Lock()
_rate_lock = asyncio.Lock()
_last_request_ts = 0.0


def _load_token_state() -> dict[str, Any] | None:
    if TOKEN_FILE.exists():
        try:
            return json.loads(TOKEN_FILE.read_text(encoding="utf-8"))
        except Exception:
            return None
    if ENV_TOKEN:
        # токен из env без refresh-возможности: живём, пока живёт токен
        return {"access_token": ENV_TOKEN, "refresh_token": None, "expires_at": 9e12}
    return None


def _save_token_state(state: dict[str, Any]) -> None:
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")


async def _refresh_tokens(state: dict[str, Any]) -> dict[str, Any]:
    refresh_token = state.get("refresh_token")
    if not refresh_token:
        raise RuntimeError(
            "Нет refresh_token для обновления. Сгенерируйте новую пару токенов "
            "в кабинете dev.hh.ru и сохраните её в "
            f"{TOKEN_FILE} как {{'access_token': '...', 'refresh_token': '...'}}."
        )
    client_id = os.environ.get("HH_CLIENT_ID", "")
    client_secret = os.environ.get("HH_CLIENT_SECRET", "")
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    if client_id:
        data["client_id"] = client_id
    if client_secret:
        data["client_secret"] = client_secret
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            "https://hh.ru/oauth/token",
            data=data,
            headers={"User-Agent": USER_AGENT},
        )
    if resp.status_code != 200:
        raise RuntimeError(
            f"Обновление токена не удалось (HTTP {resp.status_code}): "
            f"{resp.text[:300]}. Получите новую пару токенов на dev.hh.ru."
        )
    payload = resp.json()
    new_state = {
        "access_token": payload["access_token"],
        "refresh_token": payload.get("refresh_token", refresh_token),
        # expires_in ~ 14 дней (1209600 с); храним абсолютное время истечения
        "expires_at": time.time() + int(payload.get("expires_in", 1209600)),
    }
    _save_token_state(new_state)
    return new_state


async def _ensure_access_token() -> str | None:
    """Возвращает актуальный access_token или None (анонимный режим)."""
    state = _load_token_state()
    if not state or not state.get("access_token"):
        return None
    expires_at = state.get("expires_at", 9e12)
    if expires_at - 300 > time.time():
        return state["access_token"]
    async with _token_lock:
        state = _load_token_state() or state
        if state.get("expires_at", 9e12) - 300 <= time.time():
            state = await _refresh_tokens(state)
        return state["access_token"]


async def _rate_limit_wait() -> None:
    global _last_request_ts
    async with _rate_lock:
        now = time.monotonic()
        wait = RATE_INTERVAL - (now - _last_request_ts)
        if wait > 0:
            await asyncio.sleep(wait)
        _last_request_ts = time.monotonic()


def _fmt(data: Any, limit: int = RESP_LIMIT) -> str:
    text = json.dumps(data, ensure_ascii=False, indent=None)
    if len(text) > limit:
        return text[:limit] + f"\n…[ответ обрезан до {limit} символов; уточните параметры запроса]"
    return text


async def _hh_get(
    path: str,
    params: dict[str, Any] | None = None,
    retry_on_auth: bool = True,
) -> dict[str, Any]:
    """GET к api.hh.ru с rate-limit, авто-refresh на 401 и retry на 429."""
    params = {k: v for k, v in (params or {}).items() if v not in (None, "", [])}
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    token = await _ensure_access_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    retries = 0
    while True:
        await _rate_limit_wait()
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"{BASE_URL}{path}", params=params, headers=headers)

        if resp.status_code == 401 and retry_on_auth:
            # токен просрочен или невалиден — пробуем обновить и повторить
            state = _load_token_state()
            if state and state.get("refresh_token"):
                await _refresh_tokens(state)
                token = await _ensure_access_token()
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                retry_on_auth = False
                continue
            return {"error": "HTTP 401: требуется валидный токен hh.ru (см. README)"}

        if resp.status_code == 429 and retries < 3:
            retries += 1
            await asyncio.sleep(1.5 * retries)
            continue

        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = resp.text[:500]
            return {"error": f"HTTP {resp.status_code}", "detail": body}

        try:
            return resp.json()
        except Exception:
            return {"error": "не удалось разобрать ответ", "raw": resp.text[:500]}

# ----------------------------------------------------------------------------
# MCP-сервер и инструменты
# ----------------------------------------------------------------------------

mcp = FastMCP(
    "hh-ru",
    instructions=(
        "Инструменты для API hh.ru. Типовые сценарии: поиск вакансий по фильтрам, "
        "анализ работодателей, справочники регионов и профессиональных ролей, "
        "работа с резюме и откликами (нужен токен). Для фильтров area/experience/employment/"
        "schedule/professional_role сначала найдите коды через find_area / "
        "find_professional_role / get_dictionary. Поиск ограничен глубиной 2000 записей "
        "(page*per_page<=2000). Ответы обрезаны — при необходимости уточняйте параметры."
    ),
)


@mcp.tool
async def search_vacancies(
    text: str = "",
    area: list[str] | None = None,
    experience: str = "",
    employment: str = "",
    schedule: str = "",
    professional_role: list[str] | None = None,
    employer_id: str = "",
    salary: int | None = None,
    only_with_salary: bool = False,
    period: int | None = None,
    order_by: str = "",
    search_field: str = "",
    page: int = 0,
    per_page: int = 20,
) -> str:
    """Поиск вакансий hh.ru (GET /vacancies, анонимно).

    text — поисковая фраза (поддерживается язык запросов hh.ru, напр. "Python AND NOT Django");
    area — коды регионов, напр. ["1"] Москва, ["113"] Россия (коды: find_area);
    experience — noExperience | between1And3 | between3And6 | moreThan6;
    employment — full | part | project | volunteer | probation;
    schedule — fullDay | shift | flexible | remote | flyInFlyOut;
    professional_role — коды ролей (find_professional_role);
    salary — нижняя граница зарплаты (RUR) вместе с only_with_salary=True;
    period — за последние N дней (макс. 30);
    order_by — publication_time | salary_desc | salary_asc_and_down_from | distance | relevance;
    search_field — name | company_name | description;
    page/per_page — пагинация, per_page<=100, page*per_page<=2000.
    """
    if per_page > 100:
        per_page = 100
    if period and period > 30:
        period = 30
    if page * per_page >= MAX_PAGE_DEPTH:
        return json.dumps({"error": "ограничение hh.ru: page*per_page < 2000"}, ensure_ascii=False)
    params: dict[str, Any] = {"page": page, "per_page": per_page}
    if text:
        params["text"] = text
    if area:
        params["area"] = area
    if experience:
        params["experience"] = experience
    if employment:
        params["employment"] = employment
    if schedule:
        params["schedule"] = schedule
    if professional_role:
        params["professional_role"] = professional_role
    if employer_id:
        params["employer_id"] = employer_id
    if salary is not None:
        params["salary"] = salary
    if only_with_salary:
        params["only_with_salary"] = "true"
    if period:
        params["period"] = period
    if order_by:
        params["order_by"] = order_by
    if search_field:
        params["search_field"] = search_field
    data = await _hh_get("/vacancies", params)
    return _fmt(data)


@mcp.tool
async def get_vacancy(vacancy_id: str) -> str:
    """Полная карточка вакансии по ID (GET /vacancies/{id}): описание, ключевые навыки, зарплата, контакты."""
    data = await _hh_get(f"/vacancies/{vacancy_id}")
    return _fmt(data)


@mcp.tool
async def get_similar_vacancies(vacancy_id: str) -> str:
    """Похожие вакансии (GET /vacancies/{id}/similar_vacancies)."""
    data = await _hh_get(f"/vacancies/{vacancy_id}/similar_vacancies")
    return _fmt(data)


@mcp.tool
async def search_employers(text: str = "", area: str = "", page: int = 0, per_page: int = 20) -> str:
    """Поиск компаний-работодателей (GET /employers, анонимно). area — код региона."""
    params = {"page": page, "per_page": min(per_page, 100)}
    if text:
        params["text"] = text
    if area:
        params["area"] = area
    data = await _hh_get("/employers", params)
    return _fmt(data)


@mcp.tool
async def get_employer(employer_id: str) -> str:
    """Профиль работодателя по ID (GET /employers/{id}): название, описание, отрасль, сайты, вакансии."""
    data = await _hh_get(f"/employers/{employer_id}")
    return _fmt(data, limit=12000)


@mcp.tool
async def get_employer_active_vacancies(employer_id: str, page: int = 0, per_page: int = 20) -> str:
    """Активные вакансии работодателя (GET /employers/{id}/vacancies/active, анонимно)."""
    data = await _hh_get(f"/employers/{employer_id}/vacancies/active", {"page": page, "per_page": per_page})
    return _fmt(data)


@mcp.tool
async def find_area(query: str) -> str:
    """Поиск кода региона по названию (GET /suggest/areas): 'Москва', 'Екатеринбург', 'Казань'..."""
    data = await _hh_get("/suggest/areas", {"q": query, "per_page": 20})
    return _fmt(data)


@mcp.tool
async def get_area_tree(area_id: str = "113") -> str:
    """Дерево регионов. По умолчанию Россия (113); передайте другой ID страны/региона."""
    data = await _hh_get(f"/areas/{area_id}")
    return _fmt(data, limit=14000)


@mcp.tool
async def find_professional_role(query: str) -> str:
    """Поиск кода профессиональной роли по названию (GET /professional_roles): 'Аналитик', 'Бухгалтер'..."""
    data = await _hh_get("/professional_roles")
    result = []
    q = query.lower()
    for category in data or []:
        for role in category.get("roles", []):
            if q in role.get("name", "").lower():
                result.append({"category": category.get("name"), "id": role["id"], "name": role["name"]})
    if not result:
        return json.dumps({"not_found": query}, ensure_ascii=False)
    return _fmt(result[:30])


@mcp.tool
async def get_specializations() -> str:
    """Справочник специализаций (GET /specializations): коды для фильтра вакансий."""
    data = await _hh_get("/specializations")
    return _fmt(data, limit=14000)


@mcp.tool
async def get_industries() -> str:
    """Справочник отраслей работодателей (GET /industries)."""
    data = await _hh_get("/industries")
    return _fmt(data)


@mcp.tool
async def get_dictionary() -> str:
    """Словари фильтров (GET /dictionaries): experience, employment, schedule, vacancy_search_order и др."""
    data = await _hh_get("/dictionaries")
    return _fmt(data, limit=14000)


@mcp.tool
async def me() -> str:
    """Информация об авторизованном пользователе (GET /me). Требует токен; анонимно вернёт ошибку 403."""
    data = await _hh_get("/me")
    return _fmt(data)


@mcp.tool
async def my_resumes() -> str:
    """Свои резюме (GET /resumes/mine). Требует пользовательский токен соискателя."""
    data = await _hh_get("/resumes/mine")
    return _fmt(data)


@mcp.tool
async def get_resume(resume_id: str) -> str:
    """Просмотр резюме (GET /resumes/{id}). Своё — по токену соискателя; чужие — только с платным
    доступом работодателя к базе резюме, иначе API вернёт 403."""
    data = await _hh_get(f"/resumes/{resume_id}")
    return _fmt(data, limit=16000)


@mcp.tool
async def search_resumes(
    text: str = "",
    area: str = "",
    professional_role: str = "",
    experience: str = "",
    period: int | None = None,
    order_by: str = "relevance",
    page: int = 0,
    per_page: int = 20,
) -> str:
    """Поиск по базе резюме (GET /resumes). Нужен токен работодателя и ОПЛАЧЕННАЯ подписка
    на базу резюме — иначе 403. experience: noExperience|between1And3|between3And6|moreThan6;
    order_by: relevance|published_at_desc|salary_desc; глубина выдачи: page*per_page<=2000."""
    if per_page > 100:
        per_page = 100
    if period and period > 30:
        period = 30
    params: dict[str, Any] = {"page": page, "per_page": per_page, "order_by": order_by}
    if text:
        params["text"] = text
    if area:
        params["area"] = area
    if professional_role:
        params["professional_role"] = professional_role
    if experience:
        params["experience"] = experience
    if period:
        params["period"] = period
    data = await _hh_get("/resumes", params)
    return _fmt(data)


@mcp.tool
async def get_applications(vacancy_id: str = "", page: int = 0, per_page: int = 20) -> str:
    """Отклики/приглашения работодателя (GET /negotiations). Требует токен работодателя.
    vacancy_id — отклики по конкретной вакансии; без него вернёт список коллекций."""
    params = {"page": page, "per_page": min(per_page, 50)}
    if vacancy_id:
        params["vacancy_id"] = vacancy_id
    data = await _hh_get("/negotiations", params)
    return _fmt(data)


ALLOWED_PATHS = (
    "/vacancies",
    "/employers",
    "/areas",
    "/metro",
    "/dictionaries",
    "/specializations",
    "/professional_roles",
    "/industries",
    "/suggest/areas",
    "/suggest/vacancy_names",
    "/suggest/companies",
    "/universities",
    "/languages",
    "/salaries",
    "/me",
    "/resumes/mine",
    "/negotiations",
    "/employer/vacancies",
)


@mcp.tool
async def hh_api_get(path: str, query: str = "") -> str:
    """Универсальный анонимный GET к api.hh.ru по allowlist известных путей.
    path — напр. '/vacancies' или '/employers/1455';
    query — строка URL-параметров, напр. 'text=python&area=1&page=0'.
    Для авторизованных методов используйте специализированные инструменты."""
    if not path.startswith("/"):
        path = "/" + path
    clean = path.split("?")[0]
    allowed = any(clean == p or clean.startswith(p + "/") or clean.startswith(p + "?") for p in ALLOWED_PATHS)
    if not allowed:
        return json.dumps(
            {"error": f"путь {path} не в allowlist", "allowed_prefixes": ALLOWED_PATHS},
            ensure_ascii=False,
        )
    params: dict[str, Any] = {}
    for pair in query.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            params[k] = v
    data = await _hh_get(clean, params)
    return _fmt(data)


# ----------------------------------------------------------------------------
# Защита сервера (Bearer) и запуск
# ----------------------------------------------------------------------------

def build_app():
    """Собирает ASGI-приложение; при заданном MCP_AUTH_TOKEN добавляет проверку Bearer."""
    if not MCP_AUTH_TOKEN:
        return mcp.http_app(path=PATH)
    from starlette.middleware import Middleware
    from starlette.responses import Response
    from starlette.types import ASGIApp, Receive, Scope, Send

        class BearerCheckMiddleware:
        def __init__(self, app: ASGIApp, token: str) -> None:
            self.app = app
            self.token = token

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] == "http" and scope.get("path", "").startswith(PATH):
                headers = {k: v for k, v in scope.get("headers", [])}
                auth = headers.get(b"x-mcp-token", b"").decode("latin-1")
                if auth != self.token:
                    resp = Response("Unauthorized", status_code=401)
                    await resp(scope, receive, send)
                    return
            await self.app(scope, receive, send)


    return mcp.http_app(path=PATH, middleware=[Middleware(BearerCheckMiddleware, token=MCP_AUTH_TOKEN)])


if __name__ == "__main__":
    app = build_app()
    uvicorn.run(app, host=HOST, port=PORT)
    # Альтернатива без собственного uvicorn (если версия fastmcp не поддерживает http_app):
    # mcp.run(transport="http", host=HOST, port=PORT, path=PATH)
