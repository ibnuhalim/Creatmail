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
    const subject = message.headers.get("subject") || "";
    const raw = await new Response(message.raw).text();

    const mailbox = await env.DB.prepare(`
      SELECT email FROM mailboxes
      WHERE email = ?
      AND expires_at > ?
      LIMIT 1
    `).bind(to, Date.now()).first();

    if (!mailbox) {
      message.setReject("Mailbox not found or expired");
      return;
    }

    await env.DB.prepare(`
      INSERT INTO emails
      (mailbox_email, from_addr, to_addr, subject, raw, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      to,
      from,
      to,
      subject,
      raw,
      Date.now()
    ).run();
  }
};

async function createMail(env) {
  const username = randomString(10);
  const password = randomString(16);
  const email = `${username}@${env.DOMAIN}`.toLowerCase();

  const now = Date.now();
  const ttlHours = Number(env.TTL_HOURS || 24);
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
    expires_at: expiresAt
  });
}

async function getInbox(request, env) {
  const body = await safeJson(request);
  const auth = await checkAuth(env, body.email, body.password);

  if (!auth.ok) {
    return json({ success: false, error: auth.error }, 401);
  }

  const email = body.email.toLowerCase();

  const data = await env.DB.prepare(`
    SELECT id, from_addr, to_addr, subject, created_at
    FROM emails
    WHERE mailbox_email = ?
    ORDER BY created_at DESC
    LIMIT 50
  `).bind(email).all();

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

  const msg = await env.DB.prepare(`
    SELECT *
    FROM emails
    WHERE id = ?
    AND mailbox_email = ?
    LIMIT 1
  `).bind(id, email).first();

  if (!msg) {
    return json({ success: false, error: "Message not found" }, 404);
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

  await env.DB.prepare(`DELETE FROM emails WHERE mailbox_email = ?`)
    .bind(email)
    .run();

  await env.DB.prepare(`DELETE FROM mailboxes WHERE email = ?`)
    .bind(email)
    .run();

  return json({
    success: true,
    message: "Mailbox deleted"
  });
}

async function cleanup(env) {
  const now = Date.now();

  await env.DB.prepare(`
    DELETE FROM emails
    WHERE mailbox_email IN (
      SELECT email FROM mailboxes WHERE expires_at <= ?
    )
  `).bind(now).run();

  await env.DB.prepare(`
    DELETE FROM mailboxes WHERE expires_at <= ?
  `).bind(now).run();

  return json({
    success: true,
    message: "Expired mailboxes cleaned"
  });
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
