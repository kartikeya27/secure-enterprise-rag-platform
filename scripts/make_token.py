"""Mint ONLY local/demo tokens. Production identity comes from an OIDC issuer."""
import argparse
import os
import time
import jwt


def main():
    parser = argparse.ArgumentParser(description='Generate an expiring local demo bearer token')
    parser.add_argument('--tenant', required=True)
    parser.add_argument('--subject', default='demo-user')
    parser.add_argument('--roles', default='data_steward')
    parser.add_argument('--groups', default='finance')
    parser.add_argument('--clearance', default='restricted', choices=['public','internal','confidential','restricted'])
    args = parser.parse_args()
    if os.getenv('APP_ENV', 'local') != 'local' or os.getenv('AUTH_MODE', 'local') != 'local':
        raise SystemExit('Refusing to mint demo tokens outside local mode')
    secret = os.environ.get('LOCAL_JWT_SECRET', '')
    if len(secret) < 32:
        raise SystemExit('LOCAL_JWT_SECRET missing or too short')
    now = int(time.time())
    claims = dict(sub=args.subject, tenant_id=args.tenant,
                  roles=[v.strip() for v in args.roles.split(',') if v.strip()],
                  groups=[v.strip() for v in args.groups.split(',') if v.strip()],
                  clearance=args.clearance, iat=now, exp=now+3600,
                  iss=os.getenv('AUTH_ISSUER','secure-rag-local'),
                  aud=os.getenv('AUTH_AUDIENCE','secure-rag-api'))
    print(jwt.encode(claims, secret, algorithm='HS256'))


if __name__ == '__main__':
    main()
