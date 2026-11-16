# Member Portal

A small responsive registration and login app built with HTML, CSS, browser JavaScript, Node.js, and MongoDB Atlas. New accounts are stored in MongoDB. Passwords are hashed with Node's built in scrypt, and login state is kept in a signed, HTTP-only cookie.

## Run locally

Requirements: Node.js 20 or newer and a MongoDB database (a free MongoDB Atlas cluster works).

1. In MongoDB Atlas, create a database user and allow your current IP address in Network Access.
2. Copy `.env.example` to `.env` and fill in your Atlas connection string and a random session secret.
3. In a terminal in this folder, run:

   ```sh
   npm install
   npm start
   ```

4. Visit <http://localhost:3000>.

The app creates its `users` collection and unique email index on first start. It does not include demo accounts or save passwords in plain text.

## Put it online with Render

This is a Node.js app, so GitHub Pages alone cannot run the login server. Use Render for the app and MongoDB Atlas for the database.

1. Create a new, empty GitHub repository under your account. Do not commit `.env` or database credentials.
2. From this project folder, connect the existing local Git repository to that new repository and push the prepared `main` branch:

   ```sh
   git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
   git push -u origin main
   ```

3. In Render, create a **Web Service** connected to your GitHub repository. Set **Build Command** to `npm install` and **Start Command** to `npm start`.
4. Add these environment variables in the Render service settings:
   - `MONGODB_URI`: your MongoDB Atlas connection string (replace its password placeholder; URL-encode special characters in the password).
   - `MONGODB_DB`: `login_app` (optional; this is the default).
   - `SESSION_SECRET`: a long random value. You can generate one with `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"`.
   - `NODE_ENV`: `production`.
5. In MongoDB Atlas Network Access, allow the outbound IP addresses listed for your Render service. If you use a setup without stable outbound IPs, Atlas can allow `0.0.0.0/0`; keep the database password strong and use a database user with access only to this app's database.
6. Deploy the service. Render will show the public URL when the build finishes. Registration and login are available at that URL.

Render supplies the `PORT` environment variable. Keep the MongoDB URI and session secret in Render's environment settings only, never in source files.

## API

- `POST /api/register` — create an account and sign in.
- `POST /api/login` — sign in with an existing account.
- `GET /api/me` — return the current signed-in user.
- `POST /api/logout` — clear the login cookie.

## Source and license

The original page design and starter assets are based on [jovbcorreia/loginPage](https://github.com/jovbcorreia/loginPage), released under the MIT License. This version retains that attribution and adds MongoDB-backed accounts and server-side authentication.

Assignment repository: `Assignment16-11`.
