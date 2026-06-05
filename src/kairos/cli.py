"""`kairos` console entrypoint — instant local instance (SQLite + demo auth)."""

import argparse
import os


def main():
    parser = argparse.ArgumentParser(description="Run a Kairos scheduling-poll server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8003)
    parser.add_argument("--db", default=None, help="sqlite path or KAIROS_DB_URL (default ./kairos.db)")
    args = parser.parse_args()

    if args.db:
        os.environ["KAIROS_DB_URL"] = args.db if "://" in args.db else f"sqlite:///{args.db}"

    import uvicorn

    from kairos import settings
    print(f"Kairos → http://{args.host}:{args.port}{settings.PREFIX}/  "
          f"(auth={settings.AUTH_MODE}, db={os.environ.get('KAIROS_DB_URL', 'sqlite:///kairos.db')})")
    uvicorn.run("kairos.main:app", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
