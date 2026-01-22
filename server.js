import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

const {
  TS_HOST,
  TS_TRUSTED_AUTH_SECRET,
  PORT = 4000
} = process.env;

/**
 * LOGIN ENDPOINT
 * Creates a ThoughtSpot trusted-auth token
 */
app.post("/auth/login", (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: "Username required" });
  }

  const token = jwt.sign(
    {
      sub: username,
      auto_create: true,
      exp: Math.floor(Date.now() / 1000) + 300
    },
    TS_TRUSTED_AUTH_SECRET
  );

  res.json({
    authToken: token,
    tsLoginUrl: `${TS_HOST}/callosum/v1/tspublic/v1/session/login/token`
  });
});

/**
 * LOGOUT
 */
app.post("/auth/logout", (_, res) => {
  res.clearCookie("ts-session");
  res.sendStatus(200);
});

app.listen(PORT, () =>
  console.log(`Backend running on port ${PORT}`)
);
