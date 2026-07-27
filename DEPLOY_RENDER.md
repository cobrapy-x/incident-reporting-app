# Deploy the backend to Render (free, for the prototype)

Render runs your `Dockerfile` as a free web service with automatic HTTPS. No
credit card needed.

> **Prototype limits (free plan):** the service **sleeps after ~15 min idle**
> (the next request wakes it in ~30s), and there's **no persistent disk**, so the
> SQLite database is **temporary** — it resets on each redeploy. Perfect for
> testing; move to a persistent host before real use.

## Step 1 — Put the project on GitHub

Create an empty repo on github.com (e.g. `incident-backend`), then from this
folder:

```bash
git init
git add .
git commit -m "Encrypted incident-reporting app + backend"
git branch -M main
git remote add origin https://github.com/<your-username>/incident-backend.git
git push -u origin main
```

(`.gitignore` already keeps your database and keys out of the repo.)

## Step 2 — Create the Render service

1. Sign up at https://render.com (free, no card).
2. Click **New +** → **Blueprint**.
3. Connect your GitHub and pick the `incident-backend` repo.
4. Render reads `render.yaml` and shows a service named `incident-backend`
   (Docker, Free plan). Click **Apply** / **Create**.
   - If Blueprint gives trouble, use **New +** → **Web Service** instead, pick the
     repo, choose **Docker**, select the **Free** plan, and create it.
5. Wait for the first build (a few minutes). When it's live you'll get a URL like:
   ```
   https://incident-backend.onrender.com
   ```

## Step 3 — Point the app at it

Open the app, and on the sign-in screen set **Server address** to your Render
URL (e.g. `https://incident-backend.onrender.com`). Create an account and use it
as normal.

Tip: the first action after the app has been idle a while may take ~30 seconds
while Render wakes the server — that's the free-tier sleep, not a bug.

## Step 4 — Check it's up

Visit `https://<your-app>.onrender.com/docs` in a browser — you should see the
interactive API page.

## When you outgrow the prototype

- **Keep data + always-on, still free:** Oracle Cloud "Always Free" VM (more
  setup) — run the same Docker image there.
- **Easiest paid persistence:** add a Render paid instance + disk, or use
  Railway / Google Cloud Run.
