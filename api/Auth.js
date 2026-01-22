import jwt from "jsonwebtoken";

export default function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: "Username required" });
  }

  const token = jwt.sign(
    {
      sub: username,
      auto_create: true,
      exp: Math.floor(Date.now() / 1000) + 300,
    },
    process.env.TS_TRUSTED_AUTH_SECRET
  );

  res.status(200).json({ authToken: token });
}
