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

    if (request.method === "OPTIONS") return cors();

    if (url.pathname === "/") {
      return json({
        success: true,
        service: "TMP MAIL API",
        routes: {
          domains: "GET /domains",
          create: "POST /create",
          login: "POST /login",
          inbox: "POST /inbox",
          message: "POST /message",
          delete: "DELETE /delete",
          cleanup: "POST /cleanup"
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

    if (url.pathname === "/create") return await createMail(request, env);
    if (url.pathname === "/login") return await login(request, env);
    if (url.pathname === "/inbox") return await getInbox(request, env);
    if (url.pathname === "/message") return await getMessage(request, env);
    if (url.pathname === "/delete") return await deleteMailbox(request, env);
    if (url.pathname === "/cleanup") return await cleanup(env);

    return json({ success: false, error: "Route not found" }, 404);
  } catch (err) {
    return json({
      success: false,
      error: "WORKER_EXCEPTION",
      message: err?.message || String(err),
      stack: err?.stack || ""
    }, 500);
  }
}

/* =========================
   CREATE + LOGIN
========================= */

async function createMail(request, env) {
  const body = await safeJson(request);
  const domains = getAllowedDomains(env);

  if (domains.length === 0) {
    return json({ success: false, error: "No domains configured" }, 500);
  }

  let domain = String(body.domain || "").trim().toLowerCase();
  if (!domain) domain = getDefaultDomain(env);

  if (!domains.includes(domain)) {
    return json({
      success: false,
      error: "Invalid domain",
      allowed_domains: domains
    }, 400);
  }

  let username = randomString(10);
  let email = `${username}@${domain}`;

  while (await emailExists(env, email)) {
    username = randomString(10);
    email = `${username}@${domain}`;
  }

  const password = randomString(16);
  const now = Date.now();
  const expiresAt = now + Number(env.MAILBOX_TTL_HOURS || 24) * 60 * 60 * 1000;

  await env.DB.prepare(`
    INSERT INTO mailboxes (
      email,
      username,
      password,
      created_at,
      expires_at
    )
    VALUES (?, ?, ?, ?, ?)
  `).bind(email, username, password, now, expiresAt).run();

  return json({
    success: true,
    email,
    password,
    expires_at: expiresAt
  });
}

async function login(request, env) {
  const auth = await authMailPassword(request, env);

  if (!auth.ok) {
    return json({
      success: false,
      error: auth.error
    }, 401);
  }

  return json({
    success: true,
    email: auth.email,
    expires_at: auth.account.expires_at
  });
}

async function authMailPassword(request, env) {
  const body = await safeJson(request);

  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "").trim();

  if (!email || !password) {
    return {
      ok: false,
      error: "email dan password wajib"
    };
  }

  const account = await env.DB.prepare(`
    SELECT *
    FROM mailboxes
    WHERE email = ?
    AND password = ?
    LIMIT 1
  `).bind(email, password).first();

  if (!account) {
    return {
      ok: false,
      error: "Invalid email or password"
    };
  }

  if (account.expires_at <= Date.now()) {
    return {
      ok: false,
      error: "Mailbox expired"
    };
  }

  return {
    ok: true,
    email,
    password,
    account,
    body
  };
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

/* =========================
   API
========================= */

async function getInbox(request, env) {
  const auth = await authMailPassword(request, env);

  if (!auth.ok) {
    return json({ success: false, error: auth.error }, 401);
  }

  await cleanupExpired(env);

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
  `).bind(auth.email).all();

  return json({
    success: true,
    email: auth.email,
    count: data.results.length,
    messages: data.results
  });
}

async function getMessage(request, env) {
  const auth = await authMailPassword(request, env);

  if (!auth.ok) {
    return json({ success: false, error: auth.error }, 401);
  }

  const id = Number(auth.body.id || 0);

  if (!id) {
    return json({
      success: false,
      error: "id required"
    }, 400);
  }

  const msg = await env.DB.prepare(`
    SELECT *
    FROM emails
    WHERE id = ?
    AND mailbox_email = ?
    LIMIT 1
  `).bind(id, auth.email).first();

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
      subject: msg.subject || parsed.subject,
      preview: msg.preview || parsed.preview,
      otp: parsed.otp,
      text: parsed.text,
      html: parsed.html,
      created_at: msg.created_at,
      expires_at: msg.expires_at
    }
  });
}

async function deleteMailbox(request, env) {
  const auth = await authMailPassword(request, env);

  if (!auth.ok) {
    return json({ success: false, error: auth.error }, 401);
  }

  await env.DB.prepare(`
    DELETE FROM emails
    WHERE mailbox_email = ?
  `).bind(auth.email).run();

  await env.DB.prepare(`
    DELETE FROM mailboxes
    WHERE email = ?
  `).bind(auth.email).run();

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

/* =========================
   EMAIL HANDLER
========================= */

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
    parsed.subject,
    raw,
    parsed.preview,
    now,
    expiresAt
  ).run();
}

/* =========================
   EMAIL PARSER RAPI
========================= */

function parseEmailRaw(raw) {
  const headerBody = splitHeaderBody(raw);
  const headers = parseHeaders(headerBody.headers);

  const subject = decodeMimeText(headers["subject"] || "");
  const contentType = headers["content-type"] || "";
  const transfer = headers["content-transfer-encoding"] || "";

  let text = "";
  let html = "";

  const boundary = getBoundary(contentType);

  if (boundary) {
    const parts = splitMimeParts(headerBody.body, boundary);

    for (const part of parts) {
      const partSplit = splitHeaderBody(part);
      const partHeaders = parseHeaders(partSplit.headers);

      const partType = String(partHeaders["content-type"] || "").toLowerCase();
      const partTransfer = String(partHeaders["content-transfer-encoding"] || "").toLowerCase();

      const decodedBody = decodeBody(partSplit.body, partTransfer);

      if (partType.includes("text/plain") && !text) {
        text = decodedBody;
      }

      if (partType.includes("text/html") && !html) {
        html = decodedBody;
      }
    }
  } else {
    const decodedBody = decodeBody(headerBody.body, transfer);

    if (contentType.toLowerCase().includes("text/html")) {
      html = decodedBody;
      text = htmlToText(decodedBody);
    } else {
      text = decodedBody;
    }
  }

  if (!text && html) {
    text = htmlToText(html);
  }

  text = cleanText(text);
  html = cleanHtml(html);

  const preview = makePreview(text || htmlToText(html));
  const otp = extractOtp(text || htmlToText(html) || subject);

  return {
    subject,
    text,
    html,
    preview,
    otp
  };
}

function splitHeaderBody(raw) {
  const match = String(raw || "").match(/\r?\n\r?\n/);

  if (!match) {
    return {
      headers: "",
      body: String(raw || "")
    };
  }

  const index = match.index;
  const sepLength = match[0].length;

  return {
    headers: raw.slice(0, index),
    body: raw.slice(index + sepLength)
  };
}

function parseHeaders(headerText) {
  const headers = {};
  const lines = String(headerText || "").split(/\r?\n/);
  let current = "";

  for (const line of lines) {
    if (/^\s/.test(line) && current) {
      headers[current] += " " + line.trim();
      continue;
    }

    const idx = line.indexOf(":");

    if (idx > -1) {
      current = line.slice(0, idx).toLowerCase();
      headers[current] = line.slice(idx + 1).trim();
    }
  }

  return headers;
}

function getBoundary(contentType) {
  const match = String(contentType || "").match(/boundary="?([^";]+)"?/i);
  return match ? match[1] : "";
}

function splitMimeParts(body, boundary) {
  return String(body || "")
    .split("--" + boundary)
    .map(x => x.trim())
    .filter(x => x && x !== "--" && !x.startsWith("--"));
}

function decodeBody(body, transferEncoding) {
  const enc = String(transferEncoding || "").toLowerCase();

  if (enc.includes("base64")) {
    return decodeBase64Utf8(String(body || "").replace(/\s/g, ""));
  }

  if (enc.includes("quoted-printable")) {
    return decodeQuotedPrintableUtf8(body);
  }

  return String(body || "");
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

function decodeMimeText(input) {
  if (!input) return "";

  let output = String(input);

  output = output.replace(/=\?([^?]+)\?B\?([^?]+)\?=/gi, (_, charset, data) => {
    return decodeBase64Utf8(data);
  });

  output = output.replace(/=\?([^?]+)\?Q\?([^?]+)\?=/gi, (_, charset, data) => {
    return decodeQuotedPrintableUtf8(data.replace(/_/g, " "));
  });

  return output.trim();
}

function cleanHtml(html) {
  if (!html) return "";

  return String(html)
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .trim();
}

function htmlToText(html) {
  if (!html) return "";

  return String(html)
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n")
    .replace(/<\/div>/gi, "\n")
    .replace(/<\/tr>/gi, "\n")
    .replace(/<\/td>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/\n\s+\n/g, "\n")
    .replace(/[ \t]+/g, " ")
    .trim();
}

function cleanText(text) {
  return String(text || "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function makePreview(text) {
  return cleanText(text)
    .replace(/\s+/g, " ")
    .slice(0, 160);
}

function extractOtp(text) {
  const clean = String(text || "");

  const patterns = [
    /\b(\d{4,8})\b/,
    /\bcode[:\s]+(\d{4,8})\b/i,
    /\bverification code[:\s]+(\d{4,8})\b/i
  ];

  for (const p of patterns) {
    const m = clean.match(p);
    if (m) return m[1];
  }

  return "";
}

/* =========================
   HELPERS
========================= */

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
