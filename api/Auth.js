import express from "express";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const app = express();

/**
 * IMPORTANT: Prevent Vercel caching / rewriting
 */
app.disable("etag");

/**
 * CORS — explicit, single origin
 */
app.use(
  cors({
    origin: "https://uae-survey.vercel.app",
    credentials: true,
  })
);

/**
 * Preflight handler — REQUIRED on Vercel
 */
app.options("*", cors());

/**
 * Body parser
 */
app.use(express.json());

/**
 * Force JSON responses ALWAYS
 */
app.use((req, res, next) => {
  res.setHeader("Content-Type", "application/json");
  next();
});

/**
 * LOGIN
 * Generates ThoughtSpot Trusted Auth token
 */
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  // ---- VALIDATION ----
  if (!username || !password) {
    return res
      .status(400)
      .send(JSON.stringify({ error: "Username and password required" }));
  }

  const email = username.toLowerCase().trim();
  if (!email.endsWith("@7dxperts.com")) {
    return res
      .status(403)
      .send(JSON.stringify({ error: "Only @7dxperts.com users are allowed" }));
  }

  if (!process.env.TS_TRUSTED_AUTH_SECRET || !process.env.TS_HOST) {
    return res
      .status(500)
      .send(JSON.stringify({ error: "Server authentication not configured" }));
  }

  const TS_HOST = process.env.TS_HOST;
  const TS_SECRET = process.env.TS_TRUSTED_AUTH_SECRET;

  try {
    /**
     * Step 1: Validate credentials with ThoughtSpot
     */
    const loginRes = await fetch(
      `${TS_HOST}/api/rest/2.0/auth/session/login`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          username: email,
          password,
          remember_me: false,
        }),
      }
    );

    if (!loginRes.ok) {
      return res
        .status(401)
        .send(JSON.stringify({ error: "Invalid ThoughtSpot credentials" }));
    }

    /**
     * Step 2: Generate trusted auth token
     */
    const tokenRes = await fetch(
      `${TS_HOST}/api/rest/2.0/auth/token/full`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          username: email,
          secret_key: TS_SECRET,
          validity_time_in_sec: 300,
        }),
      }
    );

    if (!tokenRes.ok) {
      return res
        .status(500)
        .send(
          JSON.stringify({
            error: "Token generation failed after valid login",
          })
        );
    }

    const tokenData = await tokenRes.json();

    /**
     * SUCCESS — explicit JSON response
     */
    return res
      .status(200)
      .send(JSON.stringify({ authToken: tokenData.token }));
  } catch (err) {
    console.error("Auth error:", err);
    return res
      .status(500)
      .send(JSON.stringify({ error: "Authentication service unavailable" }));
  }
});

/**
 * LOGOUT (optional)
 */
app.post("/auth/logout", (_req, res) => {
  return res.status(200).send(JSON.stringify({ success: true }));
});

/**
 * Local dev only
 */
if (process.env.NODE_ENV !== "production") {
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => {
    console.log(`Backend running on http://localhost:${PORT}`);
  });
}

/**
 * Export for Vercel
 */
export default app;
