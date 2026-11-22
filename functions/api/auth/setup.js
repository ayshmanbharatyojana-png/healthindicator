
const ITERATIONS = 310000;

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store"
    }
  });
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derived = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return [
    "pbkdf2",
    ITERATIONS,
    base64url(salt),
    base64url(new Uint8Array(derived))
  ].join("$");
}

async function verifySecret(received, expected) {
  const encoder = new TextEncoder();

  const a = new Uint8Array(
    await crypto.subtle.digest("SHA-256", encoder.encode(received))
  );

  const b = new Uint8Array(
    await crypto.subtle.digest("SHA-256", encoder.encode(expected))
  );

  let difference = 0;

  for (let i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }

  return difference === 0;
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.DB || !env.SETUP_SECRET) {
      return json({
        success: false,
        message: "Server configuration incomplete"
      }, 503);
    }

    const suppliedSecret =
      request.headers.get("X-Setup-Secret") || "";

    if (
      !await verifySecret(
        suppliedSecret,
        env.SETUP_SECRET
      )
    ) {
      return json({
        success: false,
        message: "Unauthorized"
      }, 401);
    }

    const contentType =
      request.headers.get("Content-Type") || "";

    if (!contentType.includes("application/json")) {
      return json({
        success: false,
        message: "JSON content required"
      }, 415);
    }

    let body;

    try {
      body = await request.json();
    } catch {
      return json({
        success: false,
        message: "Invalid JSON"
      }, 400);
    }

    const username =
      String(body.username || "").trim().toLowerCase();

    const fullName =
      String(body.full_name || "").trim();

    const password =
      typeof body.password === "string"
        ? body.password
        : "";

    const email =
      String(body.email || "").trim().toLowerCase();

    if (!/^[a-z0-9._-]{4,40}$/.test(username)) {
      return json({
        success: false,
        message: "Invalid username"
      }, 400);
    }

    if (fullName.length < 2 || fullName.length > 100) {
      return json({
        success: false,
        message: "Invalid full name"
      }, 400);
    }

    if (password.length < 12 || password.length > 128) {
      return json({
        success: false,
        message: "Password must contain 12 to 128 characters"
      }, 400);
    }

    if (email.length > 254) {
      return json({
        success: false,
        message: "Invalid email"
      }, 400);
    }

    const passwordHash = await hashPassword(password);

    // Atomic one-time initialization.
    // The database itself prevents a second Super Admin
    // from being created through this endpoint.

    const result = await env.DB.prepare(`
      INSERT INTO users (
        username,
        password_hash,
        full_name,
        email,
        role,
        block_id,
        is_active
      )
      SELECT ?, ?, ?, ?, 'SUPER_ADMIN', NULL, 1
      WHERE NOT EXISTS (
        SELECT 1 FROM users
        WHERE role = 'SUPER_ADMIN'
      )
    `).bind(
      username,
      passwordHash,
      fullName,
      email || null
    ).run();

    if (!result.meta || result.meta.changes !== 1) {
      return json({
        success: false,
        message: "Administrator already initialized"
      }, 409);
    }

    return json({
      success: true,
      message: "Super Administrator created successfully",
      username,
      role: "SUPER_ADMIN"
    }, 201);

  } catch (error) {
     console.error(
    "ADMIN_SETUP_ERROR:",
    error?.stack || error?.message || String(error)
  );

  return json({
    success: false,
    message: "Administrator initialization failed"
  }, 500);
}
