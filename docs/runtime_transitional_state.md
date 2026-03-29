# Runtime Transitional State (Factory + Legacy Human Flow)

This project currently runs in a **transitional compatibility mode**.

## Canonical boot path

- `wsgi.py` boots via `app.factory.create_app()`.
- The application factory is now the canonical runtime entrypoint.

## Human/browser flow compatibility

- Human-facing browser routes are preserved via `app/legacy_human_routes.py`.
- That module intentionally rebinds key browser paths/endpoints to legacy handlers from `app.app`.
- This preserves the existing HTML/session/navigation behavior while factory boot is in place.

## Machine/API route structure

- API/agent/OAuth/LNURL routes remain in their current structure.
- This transitional pass does **not** redesign route ownership.

## Legacy dependency (intentional)

`app.app` remains a required dependency for browser flow. The current compatibility contract still depends on monolith boot semantics, including:

- `before_request` guards/redirect behavior,
- session keys (`logged_in_pubkey`, `access_level`, `guest_label`),
- helper globals / RPC helpers,
- SocketIO/chat in-memory globals used by `/app`.

## Important compatibility notes

- `/app` is intentionally served by legacy `app.app.chat`.
- A legacy `/home` endpoint alias is preserved so `url_for("home")` in legacy templates continues to work.

---

This is an intentional **stabilization baseline**, not the final architecture.
