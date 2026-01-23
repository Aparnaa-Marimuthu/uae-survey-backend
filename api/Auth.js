export default async function handler(req, res) {
  // CORS Headers - Applied to ALL responses
  const allowedOrigins = [
    "http://localhost:5173",
    "https://uae-survey.vercel.app"
  ];
  
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin || '')) {
    res.setHeader('Access-Control-Allow-Origin', origin || '');
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  // Handle OPTIONS preflight request
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // LOGIN - Your exact Express logic
  if (req.method === 'POST') {
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
    
    const TS_SECRET = process.env.TS_TRUSTED_AUTH_SECRET;

    try {
      console.log("Validating credentials for:", email);
      
      // Step 1: Validate credentials with ThoughtSpot's real login API
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
          validity_time_in_sec: 300,
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
  } 
  // LOGOUT endpoint
  else if (req.method === 'POST' && req.url.includes('/logout')) {
    res.status(200).json({ success: true });
  }
  // Invalid method
  else {
    res.status(405).json({ error: 'Method not allowed' });
  }
}
