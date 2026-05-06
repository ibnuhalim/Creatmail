export default {
  async fetch(request, env, ctx) {
    return handle(request, env, ctx);
  },

  async email(message, env, ctx) {
    try {
      return await handleEmail(message, env, ctx);
    } catch (err) {
      console.log("EMAIL_ERROR:", err?.stack || err?.message || String(err));
      message.setReject("Internal email worker error");
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(cleanupExpired(env));
  }
};

async function handle(request, env, ctx) {
  try {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return cors();
    }

    if (url.pathname === "/") {
      return json({
        success: true,
        service: "TMP MAIL API",
        routes: {
          domains: "GET /domains",
          create: "POST /create",
          inbox: "POST /inbox",
          message: "POST /message",
          delete: "DELETE /delete",
          cleanup: "POST /cleanup",
          debug: "POST /debug-token"
        }
      });
    }

    if (url.pathname === "/domains") {
      return json({
        success: true,
        domains: getAllowedDomains(env),
        default_domain: getDefaultDomain(env)
      });
    }

    if (url.pathname === "/debug-token") {
      const auth = await authJWT(request, env);
      return json(auth);
    }

    if (url.pathname === "/create") {
      return await createMail(request, env);
    }

    if (url.pathname === "/inbox") {
      return await getInbox(request, env);
    }

    if (url.pathname === "/message") {
      return await getMessage(request, env);
    }

    if (url.pathname === "/delete") {
      return await deleteMailbox(request, env);
    }

    if (url.pathname === "/cleanup") {
      return await cleanup(env);
    }

    return json({
      success: false,
      error: "Route not found"
    }, 404);
  } catch (err) {
    return json({
      success: false,
      error: "WORKER_EXCEPTION",
      message: err?.message || String(err),
      stack: err?.stack || ""
    }, 500);
  }
}

async function createMail(request, env) {
  const body = await safeJson(request);
  const domains = getAllowedDomains(env);

  if (domains.length === 0) {
    return json({
      success: false,
      error: "No domains configured"
    }, 500);
  }

  let domain = String(body.domain || "")
    .trim()
    .toLowerCase();

  if (!domain) {
    domain = getDefaultDomain(env);
  }

  if (!domains.includes(domain)) {
    return json({
      success: false,
      error: "Invalid domain",
      allowed_domains: domains
    }, 400);
  }

  let username = randomString(10);
  let email = `${username}@${domain}`;
  let exists = await emailExists(env, email);

  while (exists) {
    username = randomString(10);
    email = `${username}@${domain}`;
    exists = await emailExists(env, email);
  }

  const password = randomString(16);
  const now = Date.now();

  const expiresAt =
    now + Number(env.MAILBOX_TTL_HOURS || 24) * 60 * 60 * 1000;

  await env.DB.prepare(`
    INSERT INTO mailboxes (
      email,
      username,
      password,
      created_at,
      expires_at
    )
    VALUES (?, ?, ?, ?, ?)
  `).bind(
    email,
    username,
    password,
    now,
    expiresAt
  ).run();

  const token = await generateJWT(env, {
    email,
    password,
    platform: "XDTOOLS",
    type: "TMPMAIL",
    tag: "xdtools101cyrus"
  });

  return json({
    success: true,
    email,
    password,
    token,
    token_type: "Bearer",
    expires_at: expiresAt
  });
}

async function emailExists(env, email) {
  const existing = await env.DB.prepare(`
    SELECT id
    FROM mailboxes
    WHERE email = ?
    LIMIT 1
  `).bind(email).first();

  return !!existing;
}

async function getInbox(request, env) {
  const auth = await authJWT(request, env);

  if (!auth.ok) {
    return json({
      success: false,
      error: auth.error
    }, 401);
  }

  await cleanupExpired(env);

  const email = String(auth.payload.email || "").toLowerCase();

  const data = await env.DB.prepare(`
    SELECT
      id,
      from_addr,
      to_addr,
      subject,
      preview,
      created_at,
      expires_at
    FROM emails
    WHERE mailbox_email = ?
    ORDER BY id DESC
  `).bind(email).all();

  return json({
    success: true,
    email,
    count: data.results.length,
    messages: data.results
  });
}

async function getMessage(request, env) {
  const auth = await authJWT(request, env);

  if (!auth.ok) {
    return json({
      success: false,
      error: auth.error
    }, 401);
  }

  const body = await safeJson(request);
  const id = Number(body.id || 0);

  if (!id) {
    return json({
      success: false,
      error: "id required"
    }, 400);
  }

  const email = String(auth.payload.email || "").toLowerCase();

  const msg = await env.DB.prepare(`
    SELECT *
    FROM emails
    WHERE id = ?
    AND mailbox_email = ?
    LIMIT 1
  `).bind(
    id,
    email
  ).first();

  if (!msg) {
    return json({
      success: false,
      error: "Message not found"
    }, 404);
  }

  const parsed = parseEmailRaw(msg.raw || "");

  return json({
    success: true,
    message: {
      id: msg.id,
      from: msg.from_addr,
      to: msg.to_addr,
      subject: msg.subject,
      preview: msg.preview,
      text: parsed.text,
      html: parsed.html,
      headers: parsed.headers,
      created_at: msg.created_at,
      expires_at: msg.expires_at
    }
  });
}

async function deleteMailbox(request, env) {
  const auth = await authJWT(request, env);

  if (!auth.ok) {
    return json({
      success: false,
      error: auth.error
    }, 401);
  }

  const email = String(auth.payload.email || "").toLowerCase();

  await env.DB.prepare(`
    DELETE FROM emails
    WHERE mailbox_email = ?
  `).bind(email).run();

  await env.DB.prepare(`
    DELETE FROM mailboxes
    WHERE email = ?
  `).bind(email).run();

  return json({
    success: true,
    message: "Mailbox deleted"
  });
}

async function cleanup(env) {
  await cleanupExpired(env);

  return json({
    success: true,
    message: "Cleanup success"
  });
}

async function cleanupExpired(env) {
  const now = Date.now();

  await env.DB.prepare(`
    DELETE FROM emails
    WHERE expires_at <= ?
  `).bind(now).run();

  await env.DB.prepare(`
    DELETE FROM mailboxes
    WHERE expires_at <= ?
  `).bind(now).run();
}

async function handleEmail(message, env, ctx) {
  const to = String(message.to || "").toLowerCase();
  const from = String(message.from || "");
  const now = Date.now();

  const mailbox = await env.DB.prepare(`
    SELECT email
    FROM mailboxes
    WHERE email = ?
    LIMIT 1
  `).bind(to).first();

  if (!mailbox) {
    message.setReject("Mailbox not found");
    return;
  }

  const raw = await new Response(message.raw).text();
  const parsed = parseEmailRaw(raw);

  const preview = createPreview(
    parsed.text || stripHtml(parsed.html || "")
  );

  const expiresAt =
    now + Number(env.MESSAGE_TTL_MINUTES || 60) * 60 * 1000;

  await env.DB.prepare(`
    INSERT INTO emails (
      mailbox_email,
      from_addr,
      to_addr,
      subject,
      raw,
      preview,
      created_at,
      expires_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    to,
    from,
    to,
    parsed.headers.subject || "",
    raw,
    preview,
    now,
    expiresAt
  ).run();
}

async function generateJWT(env, payload) {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + Number(env.JWT_EXPIRES || 86400);

  const header = {
    alg: "HS256",
    typ: "JWT"
  };

  const body = {
    ...payload,
    iss: "XDTOOLS",
    aud: "TMPMAIL",
    iat: now,
    exp,
    jti: crypto.randomUUID()
  };

  const h = base64UrlEncode(JSON.stringify(header));
  const p = base64UrlEncode(JSON.stringify(body));
  const data = `${h}.${p}`;
  const sig = await hmacSign(env.JWT_SECRET || "xdtools101cyrus", data);

  return `${data}.${sig}`;
}

async function authJWT(request, env) {
  try {
    const auth = request.headers.get("Authorization") || "";

    if (!auth.startsWith("Bearer ")) {
      return {
        ok: false,
        error: "Missing bearer token"
      };
    }

    const token = auth.slice(7).trim();
    const parts = token.split(".");

    if (parts.length !== 3) {
      return {
        ok: false,
        error: "Invalid token format"
      };
    }

    const [h, p, sig] = parts;
    const data = `${h}.${p}`;

    const validSig = await hmacSign(env.JWT_SECRET || "xdtools101cyrus", data);

    if (sig !== validSig) {
      return {
        ok: false,
        error: "Invalid token signature"
      };
    }

    const payload = JSON.parse(base64UrlDecode(p));

    if (payload.exp < Math.floor(Date.now() / 1000)) {
      return {
        ok: false,
        error: "Token expired"
      };
    }

    if (!payload.email) {
      return {
        ok: false,
        error: "Invalid token payload"
      };
    }

    return {
      ok: true,
      payload
    };
  } catch (err) {
    return {
      ok: false,
      error: err?.message || "JWT Error"
    };
  }
}

async function hmacSign(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );

  return base64UrlArrayBuffer(signature);
}

function base64UrlEncode(input) {
  return base64UrlArrayBuffer(new TextEncoder().encode(input));
}

function base64UrlArrayBuffer(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecode(input) {
  let value = input.replace(/-/g, "+").replace(/_/g, "/");

  while (value.length % 4) {
    value += "=";
  }

  return atob(value);
}

function parseEmailRaw(raw) {
  const subject =
    (raw.match(/^Subject:\s*(.*)$/im) || [])[1] || "";

  const parts = raw.split(/\r?\n\r?\n/);
  const body = parts.slice(1).join("\n\n") || "";

  return {
    headers: {
      subject: decodeMimeSubject(subject)
    },
    text: body,
    html: raw
  };
}

function createPreview(text) {
  return String(text || "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 120);
}

function stripHtml(html) {
  return String(html || "")
    .replace(/<[^>]+>/g, " ");
}

function decodeMimeSubject(subject) {
  return String(subject || "").trim();
}

function getAllowedDomains(env) {
  return String(env.DOMAINS || env.DEFAULT_DOMAIN || "xdtools.me")
    .split(",")
    .map(x => x.trim().toLowerCase())
    .filter(Boolean);
}

function getDefaultDomain(env) {
  return getAllowedDomains(env)[0] || "xdtools.me";
}

async function safeJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function randomString(length) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = new Uint8Array(length);

  crypto.getRandomValues(bytes);

  let out = "";

  for (const b of bytes) {
    out += chars[b % chars.length];
  }

  return out;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "*",
      "Access-Control-Allow-Methods": "*"
    }
  });
}

function cors() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "*",
      "Access-Control-Allow-Methods": "*"
    }
  });
}
