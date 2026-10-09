# ChatSoul signaling server

```
npm install
npm start          # listens on :3000
```

## Environment variables
| Var | Default | Notes |
|---|---|---|
| `PORT` / `HOST` | 3000 / 0.0.0.0 | |
| `SIGNAL_SECRET` | CHANGE_ME… | Must equal PHP `SIGNAL_SECRET` |
| `INTERNAL_SECRET` | CHANGE_ME… | Must equal PHP `INTERNAL_SECRET` |
| `PHP_INTERNAL_URL` | `http://127.0.0.1/chatsoul/api/matching/internal.php` | |
| `ALLOWED_ORIGINS` | `localhost,127.0.0.1` | Comma-separated hostnames |
| `NODE_ENV` | development | `production` refuses default secrets |

## Socket events
Client → server: `find`, `next`, `cancel`, `leave`, `signal {kind: offer|answer|ice, data, matchId}`, `chat`, `typing`, `media-state`.
Server → client: `ready`, `searching`, `matched {matchId, role, partner}`, `signal`, `partner-left`, `match-ended`, `chat`, `typing`, `media-state`, `banned`, `session-replaced`, `rate-limited`.

## Internal HTTP (needs `X-Internal-Secret`)
`GET /internal/stats`, `POST /internal/end-match`, `POST /internal/disconnect-user`, `POST /internal/reload-settings`. `GET /health` is public.

State is in memory (single process). To scale out, add the Socket.IO Redis adapter and a Redis-backed queue.
