"""Create local demo credentials. Never commit .env to version control."""
from pathlib import Path
import secrets
import urllib.parse

root = Path(__file__).resolve().parents[1]
src = root / '.env.example'
dst = root / '.env'
if dst.exists():
    raise SystemExit('.env already exists; refusing to overwrite existing credentials')
data = src.read_text()
for key in ('LOCAL_JWT_SECRET', 'POSTGRES_PASSWORD', 'APP_DB_PASSWORD'):
    data = data.replace('REPLACE_ME_' + key, secrets.token_urlsafe(48))
app_db_password = next(line.partition('=')[2] for line in data.splitlines() if line.startswith('APP_DB_PASSWORD='))
data = data.replace('REPLACE_ME_APP_DB_PASSWORD', urllib.parse.quote(app_db_password, safe=''))
dst.write_text(data)
dst.chmod(0o600)
print('Created .env with random secrets and restrictive permissions. DO NOT COMMIT IT.')
