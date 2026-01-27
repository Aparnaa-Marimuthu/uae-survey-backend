// api/Auth.js
import dotenv from "dotenv";
dotenv.config();

const allowedOrigins = [
  "http://localhost:5173",
  "https://uae-survey.vercel.app",
];

function setCorsHeaders(req, res) {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  // required when frontend sends cookies/credentials
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
}

export default async function handler(req, res) {
  setCorsHeaders(req, res);

  // Handle preflight
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST, OPTIONS");
    return res.status(405).json({ error: "Method not allowed" });
  }

  // parse body (Vercel will usually provide parsed body for JSON)
  const { username, password } = req.body ?? {};

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const email = username.toLowerCase().trim();

  if (!email.endsWith("@7dxperts.com")) {
    return res.status(403).json({ error: "Only @7dxperts.com users are allowed" });
  }

  const TS_HOST = process.env.TS_HOST;
  const TS_SECRET = process.env.TS_TRUSTED_AUTH_SECRET;
  if (!TS_HOST || !TS_SECRET) {
    console.error("Missing TS_HOST or TS_TRUSTED_AUTH_SECRET");
    return res.status(500).json({ error: "Server not configured" });
  }

  try {
    // Validate ThoughtSpot credentials
    const loginRes = await fetch(`${TS_HOST}/api/rest/2.0/auth/session/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ username: email, password, remember_me: false }),
    });

    if (!loginRes.ok) {
      console.log("ThoughtSpot login failed:", loginRes.status);
      return res.status(401).json({ error: "Invalid ThoughtSpot credentials" });
    }

    // Generate trusted token
    const tokenRes = await fetch(`${TS_HOST}/api/rest/2.0/auth/token/full`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        username: email,
        secret_key: TS_SECRET,
        validity_time_in_sec: 300,
      }),
    });

    if (!tokenRes.ok) {
      console.error("Trusted token generation failed:", tokenRes.status);
      return res.status(500).json({ error: "Token generation failed" });
    }

    const tokenData = await tokenRes.json();
    return res.status(200).json({ authToken: tokenData.token });
  } catch (err) {
    console.error("Auth error:", err);
    return res.status(500).json({ error: "Authentication service unavailable" });
  }
}
