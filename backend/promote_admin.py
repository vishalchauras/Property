import argparse
import asyncio
import os
import sys

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

load_dotenv()


async def promote(phone: str) -> int:
    client = AsyncIOMotorClient(os.getenv("MONGO_URL", "mongodb://localhost:27017"))
    try:
        database = client[os.getenv("DB_NAME", "real_estate_mvp")]
        result = await database.users.update_one(
            {"phone": phone},
            {"$set": {"role": "admin", "verified": True}},
        )
        if not result.matched_count:
            print("No account found for that phone number. Sign in to the app first.", file=sys.stderr)
            return 1
        print("Admin role granted.")
        return 0
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Grant the admin role to an existing PropertyFeed user.")
    parser.add_argument("phone", help="Phone number used by the existing account")
    args = parser.parse_args()
    return asyncio.run(promote(args.phone.strip()))


if __name__ == "__main__":
    raise SystemExit(main())
