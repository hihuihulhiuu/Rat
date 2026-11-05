# Nordvale Identity

Login-Portal mit Konto-Erstellung. Konten liegen serverseitig in `nordvale.sqlite3`
(Tabelle `accounts`, Passwort als PBKDF2-SHA256-Hash mit Salt). Sessions als HttpOnly-Cookie.

## Start

```bat
start.bat
```

oder manuell:

```bat
python server.py
```

Browser: <http://127.0.0.1:8081/>

## Port

Standard ist **8081**. `8080` ist häufig belegt (CEF-Remote-Debugging, Dev-Proxys) —
dann landet man im Browser auf der falschen Seite. Anderer Port:

```bat
set NV_PORT=8082 && python server.py
```

## Konfiguration (Umgebungsvariablen)

| Variable | Default | Zweck |
|---|---|---|
| `NV_PORT` | `8081` | Listen-Port |
| `NV_HOST` | `0.0.0.0` | Listen-Adresse, `127.0.0.1` für nur lokal |
| `NV_DB` | `./nordvale.sqlite3` | SQLite-Datei |
| `NV_PANEL_KEY` | `nordvale` | Schlüssel für das Panel (`#panel`) |
| `NV_ALLOW_REGISTRATION` | `1` | `0` schließt die Registrierung |
| `NV_GEO` | `1` | IP-/Geo-Lookup im Browser |
| `NV_SECURE_COOKIES` | `0` | `1` hinter HTTPS |
| `NV_TRUST_PROXY` | `0` | `1` wenn hinter einem Proxy |

## Routen

| Methode | Pfad | Zweck |
|---|---|---|
| `GET` | `/` | Login-Seite |
| `GET` | `/assets/style.css`, `/assets/app.js` | Assets (Query-String erlaubt) |
| `GET` | `/api/health` | Status |
| `GET` | `/api/me` | aktive Session |
| `POST` | `/api/register` | `{email, password, passwordConfirm, displayName}` |
| `POST` | `/api/login` | `{email, password}` |
| `POST` | `/api/logout` | Session beenden |
| `POST` | `/api/panel/unlock` | `{key}` → Panel-Session |
| `GET` | `/api/panel/overview` | Captures + Konten |
| `GET` | `/api/panel/export.json` / `.csv` | Export |

## Oberfläche

- `#login` — Anmeldung, mit Button **„Neues Konto erstellen"**
- `#register` — Registrierung, mit **„Zurück zur Anmeldung"**
- `#account` — Konto-Dashboard (Session nötig)
- `#panel` — Panel, Schlüssel aus `NV_PANEL_KEY`

## Fehlersuche

| Symptom | Ursache |
|---|---|
| Seite ohne Design | `style.css?v=2` liefert 404 → Server neu starten |
| Kein Registrieren-Button | alte `index.html` im Browser-Cache → Strg+F5 |
| Falsche Seite im Browser | Port belegt, siehe Abschnitt **Port** |
| `Port ... ist belegt` beim Start | `set NV_PORT=8082 && python server.py` |
