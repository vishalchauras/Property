# PropertyFeed

PropertyFeed is a real-estate discovery MVP with an Expo/React Native app, a FastAPI REST API, and MongoDB.

## Backend

1. Start MongoDB locally (or provide a MongoDB connection URL).
2. From `backend/`, create and activate a virtual environment, then run `pip install -r requirements.txt`.
3. Copy `.env.example` to `.env`; set `JWT_SECRET` to a long, random value before exposing the API.
4. Run `uvicorn server:app --reload`.

The API is available at `http://localhost:8000` and its OpenAPI page at `/docs`. Development OTP is fixed to `123456` and is returned only while `ENVIRONMENT=development`; configure a real SMS provider before production (OTP requests return `503` in other environments until one is configured). Demo data can be loaded with `SEED_DEMO_DATA=true` on startup.

To grant the admin role, first create the account through OTP sign-in, then run `python promote_admin.py +<phone>` from `backend/`. Admin roles are deliberately unavailable during public sign-up.

## Mobile app

1. From `frontend/`, run `npm install`.
2. Set `EXPO_PUBLIC_BACKEND_URL` to the API URL reachable from the device. Android emulator users should use `http://10.0.2.2:8000`; physical devices should use the computer's LAN address.
3. Run `npm start` and open the app in Expo Go or a development build.

## MVP flows

OTP sign-in -> vertical property reels -> search/filter properties -> property detail/save/enquiry -> owner/broker lead inbox and status pipeline. The create menu includes property, reel, and customer-requirement forms. Profile exposes saved content, notifications, requirements, and account actions. Roles supported are customer, owner, broker, and admin (admin accounts must be provisioned outside public sign-up). Property images and reel media are supplied as public URLs; connect an object-storage upload service before accepting local media uploads in production.
