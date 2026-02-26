# CallSharks Platform

Full-stack Flask app for mortgage lead subscriptions with client + admin experiences.

## Features implemented
- Secure sign up and log in with password hashing and session auth.
- Optimized auth-aware navbar on the homepage.
- Stripe subscription architecture with checkout + webhook endpoint (`/stripe/webhook`).
- Admin dashboard for:
  - editable plans,
  - coupons + free trial codes,
  - CSV lead upload/import,
  - import categorization + column mapping metadata,
  - notifications,
  - real-time users/subscription feed (`/api/admin/realtime`).
- Client dashboard for subscription management, notifications, and assigned leads table.
- Resend email integration for onboarding emails.
- `.env.example` template included.

## Quick start
1. Create and activate a virtual environment.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Copy environment template:
   ```bash
   cp .env.example .env
   ```
4. Set production secrets (especially `SECRET_KEY`, Stripe keys, and Resend API key).
5. Run app:
   ```bash
   python app.py
   ```

## Main routes
- `/` marketing homepage
- `/signup`, `/login`, `/logout`
- `/dashboard` client dashboard
- `/admin` admin dashboard
- `/api/admin/realtime` live dashboard data
- `/stripe/webhook` Stripe events

## Notes
- If Stripe keys are not configured, checkout falls back to a mock path to keep workflows testable.
- Default bootstrap admin account is created from env vars at startup.
