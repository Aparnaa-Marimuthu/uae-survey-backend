import express from "express";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const app = express();

/**
 * Explicit CORS configuration
 */
const allowedOrigins = [
  "http://localhost:5173",
  "https://uae-survey.vercel.app",
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("CORS not allowed"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

/**
 * VERY IMPORTANT for Vercel
 * Handle preflight explicitly
 */
app.options("*", cors());

app.use(express.json());

/**
 * LOGIN
 */
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const email = username.toLowerCase().trim();

  if (!email.endsWith("@7dxperts.com")) {
    return res.status(403).json({
      error: "Only @7dxperts.com users are allowed",
    });
  }

  if (!process.env.TS_TRUSTED_AUTH_SECRET) {
    return res.status(500).json({
      error: "Server authentication not configured",
    });
  }

  try {
    /**
     * Step 1 — Validate credentials
     */
    const loginRes = await fetch(`${process.env.TS_HOST}/api/rest/2.0/auth/session/login`, {
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
    });

    if (!loginRes.ok) {
      return res.status(401).json({
        error: "Invalid ThoughtSpot credentials",
      });
    }

    /**
     * Step 2 — Trusted token
     */
    const tokenRes = await fetch(`${process.env.TS_HOST}/api/rest/2.0/auth/token/full`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        username: email,
        secret_key: process.env.TS_TRUSTED_AUTH_SECRET,
        validity_time_in_sec: 300,
      }),
    });

    if (!tokenRes.ok) {
      return res.status(500).json({
        error: "Token generation failed",
      });
    }

    const tokenData = await tokenRes.json();
    res.json({ authToken: tokenData.token });
  } catch (err) {
    console.error("Auth error:", err);
    res.status(500).json({ error: "Authentication service unavailable" });
  }
});

/**
 * LOGOUT
 */
app.post("/auth/logout", (_req, res) => {
  res.status(200).json({ success: true });
});

export default app;
