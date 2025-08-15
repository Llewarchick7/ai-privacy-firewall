# AI Privacy Firewall Frontend

Minimal Node.js (Express) static frontend to demo Google OAuth login, token capture, and authenticated API calls.

- Serves `public/` at http://localhost:3000
- Login flow: calls backend `/api/users/oauth/google/login`, completes OAuth, backend redirects to `FRONTEND_URL/#token=...`
- `public/login.js` captures `#token`, stores it in `localStorage`, and uses it for API requests

## Run

1. Install Node 18+.
2. Install deps and start:

```bash
npm install
npm run dev # or npm start
```

3. Ensure backend is running at http://localhost:8000 and CORS allows http://localhost:3000 (already configured).
4. Set environment:
   - In backend: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `OAUTH_REDIRECT_URI` (or rely on defaults), `FRONTEND_URL=http://localhost:3000`.

