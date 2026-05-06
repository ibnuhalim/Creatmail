export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return cors();
    }

    if (url.pathname === "/create" && request.method === "POST") {
      return createMail(env);
    }

    if (url.pathname === "/inbox" && request.method === "POST") {
      return getInbox(request, env);
    }

    if (url.pathname === "/message" && request.method === "POST") {
      return getMessage(request, env);
    }

    if (url.pathname === "/delete" && request.method === "POST") {
      return deleteMailbox(request, env);
    }

    if (url.pathname === "/cleanup" && request.method === "POST") {
      return cleanup(env);
    }

    return json({
      success: true,
      name: "TMP Mail API",
      message_ttl: "1 hour",
      routes: {
        create: "POST /create",
        inbox: "POST /inbox",
        message: "POST /message",
        delete: "POST /delete",
        cleanup: "POST /cleanup"
      }
    });
  },

  async email(message, env, ctx) {
    const to = String(message.to || "").toLowerCase();
    const from = String(message.from || "");

    const subject = decodeMimeSubject(
      getHeader(message.headers, "subject")
    );

    const raw = await new Response(message.raw).text();

    const now = Date.now();
    const msgTtlMinutes = Number(env.MESSAGE_TTL_MINUTES || 60);
    const messageExpiresAt = now + msgTtlMinutes * 60 * 1000;

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

    await env.DB.prepare(`
      INSERT INTO emails
      (mailbox_email, from_addr, to_addr, subject, raw, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      to,
      from,
      to,
      subject,
      raw,
      now,
      messageExpiresAt
    ).run();
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(cleanupExpired(env));
  }
};

async function createMail(env) {
  const username = randomString(10);
  const password = randomString(16);
  const email = `${username}@${env.DOMAIN}`.toLowerCase();

  const now = Date.now();
  const ttlHours = Number(env.MAILBOX_TTL_HOURS || 24);
  const expiresAt = now + ttlHours * 60 * 60 * 1000;

  await env.DB.prepare(`
    INSERT INTO mailboxes
    (email, username, password, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `).bind(email, username, password, now, expiresAt).run();

  return json({
    success: true,
    email,
    password,
    expires_at: expiresAt,
    inbox_api: "/inbox",
    message_api: "/message"
  });
}

async function getInbox(request, env) {
  const body = await safeJson(request);
  const auth = await checkAuth(env, body.email, body.password);

  if (!auth.ok) {
    return json({ success: false, error: auth.error }, 401);
  }

  const email = body.email.toLowerCase();

  await cleanupExpired(env);

  const data = await env.DB.prepare(`
    SELECT id, from_addr, to_addr, subject, created_at, expires_at
    FROM emails
    WHERE mailbox_email = ?
    AND expires_at > ?
    ORDER BY created_at DESC
    LIMIT 50
  `).bind(email, Date.now()).all();

  return json({
    success: true,
    email,
    messages: data.results
  });
}

async function getMessage(request, env) {
  const body = await safeJson(request);
  const auth = await checkAuth(env, body.email, body.password);

  if (!auth.ok) {
    return json({ success: false, error: auth.error }, 401);
  }

  const email = body.email.toLowerCase();
  const id = Number(body.id || 0);

  await cleanupExpired(env);

  const msg = await env.DB.prepare(`
    SELECT *
    FROM emails
    WHERE id = ?
    AND mailbox_email = ?
    AND expires_at > ?
    LIMIT 1
  `).bind(id, email, Date.now()).first();

  if (!msg) {
    return json({ success: false, error: "Message not found or expired" }, 404);
  }

  return json({
    success: true,
    message: msg
  });
}

async function deleteMailbox(request, env) {
  const body = await safeJson(request);
  const auth = await checkAuth(env, body.email, body.password);

  if (!auth.ok) {
    return json({ success: false, error: auth.error }, 401);
  }

  const email = body.email.toLowerCase();

  await env.DB.prepare(`
    DELETE FROM emails WHERE mailbox_email = ?
  `).bind(email).run();

  await env.DB.prepare(`
    DELETE FROM mailboxes WHERE email = ?
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
      SELECT email FROM mailboxes WHERE expires_at <= ?
    )
  `).bind(now).run();

  await env.DB.prepare(`
    DELETE FROM mailboxes
    WHERE expires_at <= ?
  `).bind(now).run();
}

async function checkAuth(env, email, password) {
  if (!email || !password) {
    return { ok: false, error: "email dan password wajib diisi" };
  }

  const mailbox = await env.DB.prepare(`
    SELECT email, password, expires_at
    FROM mailboxes
    WHERE email = ?
    LIMIT 1
  `).bind(email.toLowerCase()).first();

  if (!mailbox) {
    return { ok: false, error: "Mailbox not found" };
  }

  if (mailbox.expires_at <= Date.now()) {
    return { ok: false, error: "Mailbox expired" };
  }

  if (mailbox.password !== password) {
    return { ok: false, error: "Password salah" };
  }

  return { ok: true };
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

function decodeMimeSubject(subject) {
  if (!subject) return "";

  let decoded = subject;

  decoded = decoded.replace(/=\?UTF-8\?B\?(.+?)\?=/gi, (_, encoded) => {
    try {
      const binary = atob(encoded);
      const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
      return new TextDecoder("utf-8").decode(bytes);
    } catch {
      return "";
    }
  });

  decoded = decoded.replace(/=\?UTF-8\?Q\?(.+?)\?=/gi, (_, encoded) => {
    try {
      return encoded
        .replace(/_/g, " ")
        .replace(/=([A-Fa-f0-9]{2})/g, (_, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        );
    } catch {
      return "";
    }
  });

  return decoded.trim();
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
    }
  });
}

function cors() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
    }
  });
}
