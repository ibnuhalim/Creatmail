export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      if (request.method === "OPTIONS") return cors();

      if (url.pathname === "/domains") {
        return json({
          success: true,
          domains: getAllowedDomains(env),
          default_domain: getDefaultDomain(env)
        });
      }

      if (url.pathname === "/create") {
        return createMail(env);
      }

      if (url.pathname === "/inbox") {
        return getInbox(request, env);
      }

      if (url.pathname === "/message") {
        return getMessage(request, env);
      }

      if (url.pathname === "/delete") {
        return deleteMailbox(request, env);
      }

      if (url.pathname === "/cleanup") {
        return cleanup(env);
      }

      return json({
        success: true,
        service: "TMP MAIL API",
        routes: {
          domains: "GET /domains",
          create: "POST /create",
          inbox: "POST /inbox",
          message: "POST /message",
          delete: "DELETE /delete",
          cleanup: "POST /cleanup"
        }
      });
    } catch (err) {
      return json({
        success: false,
        error: String(err?.message || err),
        stack: String(err?.stack || "")
      }, 500);
    }
  },

  async email(message, env) {
    try {
      const to = String(message.to || "").toLowerCase();
      const from = String(message.from || "");
      const domain = to.split("@")[1] || "";

      if (!getAllowedDomains(env).includes(domain)) {
        message.setReject("Domain not allowed");
        return;
      }

      const now = Date.now();

      const mailbox = await env.DB.prepare(`
        SELECT email FROM mailboxes
        WHERE email = ?
        AND expires_at > ?
        LIMIT 1
      `).bind(to, now).first();

      if (!mailbox) {
        message.setReject("Mailbox not found or expired");
        return;
      }

      const raw = await new Response(message.raw).text();
      const parsed = parseEmailRaw(raw);

      const subject = decodeMimeSubject(
        parsed.headers.subject || getHeader(message.headers, "subject")
      );

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
        subject,
        raw,
        preview,
        now,
        expiresAt
      ).run();
    } catch {
      message.setReject("Worker email error");
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(cleanupExpired(env));
  }
};

async function createMail(env) {
  const domains = getAllowedDomains(env);

  if (domains.length === 0) {
    return json({
      success: false,
      error: "No domains configured"
    }, 500);
  }

  const domain = getDefaultDomain(env);
  const username = randomString(10);
  const password = randomString(16);
  const email = `${username}@${domain}`.toLowerCase();

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
    tag: "xdtools_" + Date.now()
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
    AND expires_at > ?
    ORDER BY id DESC
  `).bind(
    email,
    Date.now()
  ).all();

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
      error: "id wajib diisi"
    }, 400);
  }

  await cleanupExpired(env);

  const email = String(auth.payload.email || "").toLowerCase();

  const msg = await env.DB.prepare(`
    SELECT *
    FROM emails
    WHERE id = ?
    AND mailbox_email = ?
    AND expires_at > ?
    LIMIT 1
  `).bind(
    id,
    email,
    Date.now()
  ).first();

  if (!msg) {
    return json({
      success: false,
      error: "Message not found or expired"
    }, 404);
  }

  const parsed = parseEmailRaw(msg.raw || "");

  return json({
    success: true,
    message: {
      id: msg.id,
      mailbox_email: msg.mailbox_email,
      from_addr: msg.from_addr,
      to_addr: msg.to_addr,
      subject: msg.subject || parsed.headers.subject || "",
      preview: msg.preview || "",
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
    message: "Expired emails and mailboxes cleaned"
  });
}

async function cleanupExpired(env) {
  const now = Date.now();

  await env.DB.prepare(`
    DELETE FROM emails
    WHERE expires_at <= ?
  `).bind(now).run();

  await env.DB.prepare(`
    DELETE FROM emails
    WHERE mailbox_email IN (
      SELECT email FROM mailboxes
      WHERE expires_at <= ?
    )
  `).bind(now).run();

  await env.DB.prepare(`
    DELETE FROM mailboxes
    WHERE expires_at <= ?
  `).bind(now).run();
}

/* =========================
   JWT MANUAL HS256
   Tanpa dependency jose
========================= */

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
  const sig = await hmacSign(env.JWT_SECRET, data);

  return `${data}.${sig}`;
}

async function authJWT(request, env) {
  const auth = request.headers.get("Authorization") || "";

  if (!auth.startsWith("Bearer ")) {
    return {
      ok: false,
      error: "Missing bearer token"
    };
  }

  try {
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
    const validSig = await hmacSign(env.JWT_SECRET, data);

    if (sig !== validSig) {
      return {
        ok: false,
        error: "Invalid token signature"
      };
    }

    const payload = JSON.parse(base64UrlDecode(p));

    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return {
        ok: false,
        error: "Token expired"
      };
    }

    if (payload.iss !== "XDTOOLS" || payload.aud !== "TMPMAIL") {
      return {
        ok: false,
        error: "Invalid token issuer or audience"
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
  } catch {
    return {
      ok: false,
      error: "Invalid token"
    };
  }
}

async function hmacSign(secret, data) {
  if (!secret) {
    throw new Error("JWT_SECRET is missing");
  }

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

/* =========================
   EMAIL PARSER
========================= */

function parseEmailRaw(raw) {
  const parts = raw.split(/\r?\n\r?\n/);
  const headerText = parts.shift() || "";
  const bodyRaw = parts.join("\n\n");

  const headers = parseHeaders(headerText);
  const contentType = headers["content-type"] || "";

  let text = "";
  let html = "";

  const boundaryMatch = contentType.match(/boundary="?([^";]+)"?/i);

  if (boundaryMatch) {
    const boundary = boundaryMatch[1];
    const sections = bodyRaw.split("--" + boundary);

    for (const section of sections) {
      const sec = section.trim();
      if (!sec || sec === "--") continue;

      const split = sec.split(/\r?\n\r?\n/);
      const secHeaderText = split.shift() || "";
      const secBody = split.join("\n\n").trim();

      const secHeaders = parseHeaders(secHeaderText);
      const secType = (secHeaders["content-type"] || "").toLowerCase();

      if (secType.includes("text/plain") && !text) {
        text = decodeEmailBody(secBody, secHeaderText).trim();
      }

      if (secType.includes("text/html") && !html) {
        html = decodeEmailBody(secBody, secHeaderText).trim();
      }
    }
  } else {
    const decoded = decodeEmailBody(bodyRaw, headerText).trim();

    if (contentType.toLowerCase().includes("text/html")) {
      html = decoded;
      text = stripHtml(decoded);
    } else {
      text = decoded;
    }
  }

  return {
    headers: {
      from: decodeMimeSubject(headers["from"] || ""),
      to: headers["to"] || "",
      subject: decodeMimeSubject(headers["subject"] || ""),
      date: headers["date"] || "",
      message_id: headers["message-id"] || "",
      content_type: headers["content-type"] || ""
    },
    text,
    html
  };
}

function parseHeaders(headerText) {
  const headers = {};
  const lines = String(headerText || "").split(/\r?\n/);

  let currentHeader = "";

  for (const line of lines) {
    if (/^\s/.test(line) && currentHeader) {
      headers[currentHeader] += " " + line.trim();
      continue;
    }

    const idx = line.indexOf(":");

    if (idx > -1) {
      currentHeader = line.slice(0, idx).toLowerCase();
      headers[currentHeader] = line.slice(idx + 1).trim();
    }
  }

  return headers;
}

function decodeEmailBody(body, headerText = "") {
  if (!body) return "";

  const lower = String(headerText || "").toLowerCase();

  if (lower.includes("base64")) {
    return decodeBase64Utf8(body.replace(/\s/g, ""));
  }

  if (lower.includes("quoted-printable")) {
    return decodeQuotedPrintableUtf8(body);
  }

  return body;
}

function decodeQuotedPrintableUtf8(input) {
  if (!input) return "";

  const cleaned = String(input).replace(/=\r?\n/g, "");
  const bytes = [];

  for (let i = 0; i < cleaned.length; i++) {
    if (
      cleaned[i] === "=" &&
      /^[A-Fa-f0-9]{2}$/.test(cleaned.slice(i + 1, i + 3))
    ) {
      bytes.push(parseInt(cleaned.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      bytes.push(cleaned.charCodeAt(i));
    }
  }

  try {
    return new TextDecoder("utf-8").decode(new Uint8Array(bytes));
  } catch {
    return cleaned;
  }
}

function decodeBase64Utf8(input) {
  try {
    const binary = atob(input);
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    return new TextDecoder("utf-8").decode(bytes);
  } catch {
    return "";
  }
}

function decodeMimeSubject(subject) {
  if (!subject) return "";

  let decoded = String(subject);

  decoded = decoded.replace(/=\?UTF-8\?B\?(.+?)\?=/gi, (_, encoded) => {
    try {
      return decodeBase64Utf8(encoded);
    } catch {
      return "";
    }
  });

  decoded = decoded.replace(/=\?UTF-8\?Q\?(.+?)\?=/gi, (_, encoded) => {
    try {
      return decodeQuotedPrintableUtf8(encoded.replace(/_/g, " "));
    } catch {
      return "";
    }
  });

  return decoded.trim();
}

/* =========================
   HELPERS
========================= */

function createPreview(text) {
  return String(text || "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 120);
}

function stripHtml(html) {
  return String(html || "")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/\s+/g, " ")
    .trim();
}

function getAllowedDomains(env) {
  return String(env.DOMAINS || env.DEFAULT_DOMAIN || "")
    .split(",")
    .map(x => x.trim().toLowerCase())
    .filter(Boolean);
}

function getDefaultDomain(env) {
  const domains = getAllowedDomains(env);

  return String(env.DEFAULT_DOMAIN || domains[0] || "")
    .trim()
    .toLowerCase();
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

function getHeader(headers, name) {
  return (
    headers.get(name) ||
    headers.get(name.toLowerCase()) ||
    headers.get(name.toUpperCase()) ||
    ""
  );
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS"
    }
  });
}

function cors() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS"
    }
  });
}
