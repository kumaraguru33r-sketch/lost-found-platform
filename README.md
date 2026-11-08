# FindIt - Lost & Found Community Platform

Flask + SQLite + Bootstrap 5.

## Install and run

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

On first run the database (`instance/lost_found.db`), default categories and an
admin account are created. Admin login: `admin@lostfound.local`. The password is
printed in the terminal (or set `ADMIN_PASSWORD` before the first run).

## Production notes
- Set `SECRET_KEY` and `SESSION_COOKIE_SECURE=1` (HTTPS) as environment variables.
- Run behind a WSGI server, e.g. `gunicorn app:app`.
