import express from "express";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const app = express();

// 1. EXPLICIT PREFLIGHT HANDLER - Fixes Vercel serverless OPTIONS issue
app.options("*", cors({
  origin: [
    "http://localhost:5173",
    "https://uae-survey.vercel.app"
  ],
  credentials: true,
}));

// 2. GLOBAL CORS - Unchanged
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://uae-survey.vercel.app"
    ],
    credentials: true,
  })
);

app.use(express.json());

// 3. LOG ALL REQUESTS
app.use((req, res, next) => {
  console.log("🔥 Express hit:", req.method, req.url);
  next();
});

// 4. RESPONSE INTERCEPTOR - Ensures CORS headers on ALL responses (incl. errors)
app.use((req, res, next) => {
  res.on('finish', () => {
    const origin = req.headers.origin;
    if (origin && [
      "http://localhost:5173",
      "https://uae-survey.vercel.app"
    ].includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
  });
  next();
});

// Your existing routes - UNCHANGED
app.get("/health", async (req, res) => {
  res.send("API is running...");
});

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
    console.error("Trusted Auth secret missing");
    return res.status(500).json({
      error: "Server authentication not configured",
    });
  }

  const TS_HOST = process.env.TS_HOST;
  const TS_SECRET = process.env.TS_TRUSTED_AUTH_SECRET;

  try {
    // Step 1: Validate credentials with ThoughtSpot's real login API
    console.log("Validating credentials for:", email);
    const loginRes = await fetch(`${TS_HOST}/api/rest/2.0/auth/session/login`, {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({ 
        username: email, 
        password,
        remember_me: false 
      }),
    });
    console.log("Login response:", loginRes);

    if (!loginRes.ok) {
      console.log("ThoughtSpot login failed:", loginRes.status);
      return res.status(401).json({ 
        error: "Invalid ThoughtSpot credentials" 
      });
    }

    console.log("Credentials valid, generating trusted token");

    // Step 2: Generate trusted auth token
    const tokenRes = await fetch(`${TS_HOST}/api/rest/2.0/auth/token/full`, {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({
        username: email,
        secret_key: TS_SECRET,
        validity_time_in_sec: 300, // 5 minutes
      }),
    });

    if (!tokenRes.ok) {
      console.error("Trusted token generation failed:", tokenRes.status);
      return res.status(500).json({ 
        error: "Token generation failed after valid login" 
      });
    }

    const tokenData = await tokenRes.json();
    console.log("Auth token generated successfully");

    res.json({ authToken: tokenData.token });
  } catch (err) {
    console.error("Auth error:", err);
    res.status(500).json({ error: "Authentication service unavailable" });
  }
});

app.post("/auth/logout", (_req, res) => {
  res.status(200).json({ success: true });
});

if (process.env.NODE_ENV !== "production") {
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => {
    console.log(`Backend running on http://localhost:${PORT}`);
  });
}

export default app;
