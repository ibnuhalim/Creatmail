import { SignJWT, jwtVerify } from "jose";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return cors();
    }

    if (url.pathname === "/domains") {
      return json({
        success: true,
        domains: getAllowedDomains(env)
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

    return json({
      success: true,
      service: "TMP MAIL API"
    });
  },

  async email(message, env) {
    const to =
      String(message.to || "")
        .toLowerCase();

    const from =
      String(message.from || "");

    const raw =
      await new Response(
        message.raw
      ).text();

    const parsed =
      parseEmailRaw(raw);

    const preview =
      createPreview(
        parsed.text
      );

    const mailbox =
      await env.DB.prepare(`
      SELECT *
      FROM mailboxes
      WHERE email = ?
      LIMIT 1
    `).bind(to).first();

    if (!mailbox) {
      message.setReject(
        "Mailbox not found"
      );
      return;
    }

    const now = Date.now();

    const expires =
      now +
      Number(
        env.MESSAGE_TTL_MINUTES || 60
      ) *
      60 *
      1000;

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
      parsed.headers.subject,
      raw,
      preview,
      now,
      expires
    ).run();
  }
};

async function createMail(env) {
  const domains =
    getAllowedDomains(env);

  const domain =
    domains[0];

  const username =
    randomString(10);

  const password =
    randomString(16);

  const email =
    `${username}@${domain}`;

  const now = Date.now();

  const expires =
    now +
    Number(
      env.MAILBOX_TTL_HOURS || 24
    ) *
      60 *
      60 *
      1000;

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
    expires
  ).run();

  const token =
    await generateJWT(env, {
      email,
      password,
      platform: "XDTOOLS",
      type: "TMPMAIL",
      tag:
        "xdtools_" +
        Date.now()
    });

  return json({
    success: true,
    email,
    password,
    token,
    token_type: "Bearer",
    expires_at: expires
  });
}

async function getInbox(
  request,
  env
) {
  const auth =
    await authJWT(
      request,
      env
    );

  if (!auth.ok) {
    return json({
      success: false,
      error: auth.error
    }, 401);
  }

  const data =
    await env.DB.prepare(`
    SELECT
      id,
      from_addr,
      subject,
      preview,
      created_at
    FROM emails
    WHERE mailbox_email = ?
    ORDER BY id DESC
  `).bind(
      auth.payload.email
    ).all();

  return json({
    success: true,
    email:
      auth.payload.email,
    messages:
      data.results
  });
}

async function getMessage(
  request,
  env
) {
  const auth =
    await authJWT(
      request,
      env
    );

  if (!auth.ok) {
    return json({
      success: false,
      error: auth.error
    }, 401);
  }

  const body =
    await request.json();

  const msg =
    await env.DB.prepare(`
    SELECT *
    FROM emails
    WHERE id = ?
    AND mailbox_email = ?
    LIMIT 1
  `).bind(
      body.id,
      auth.payload.email
    ).first();

  if (!msg) {
    return json({
      success: false,
      error:
        "Message not found"
    }, 404);
  }

  const parsed =
    parseEmailRaw(
      msg.raw || ""
    );

  return json({
    success: true,
    message: {
      id: msg.id,
      from:
        msg.from_addr,
      subject:
        msg.subject,
      preview:
        msg.preview,
      text:
        parsed.text,
      html:
        parsed.html,
      headers:
        parsed.headers,
      created_at:
        msg.created_at
    }
  });
}

async function generateJWT(
  env,
  payload
) {
  const secret =
    new TextEncoder().encode(
      env.JWT_SECRET
    );

  return await new SignJWT(
    payload
  )
    .setProtectedHeader({
      alg: "HS256",
      typ: "JWT"
    })
    .setIssuer(
      "XDTOOLS"
    )
    .setAudience(
      "TMPMAIL"
    )
    .setIssuedAt()
    .setExpirationTime(
      Math.floor(
        Date.now() / 1000
      ) +
        Number(
          env.JWT_EXPIRES || 86400
        )
    )
    .setJti(
      crypto.randomUUID()
    )
    .sign(secret);
}

async function authJWT(
  request,
  env
) {
  const auth =
    request.headers.get(
      "Authorization"
    ) || "";

  if (
    !auth.startsWith(
      "Bearer "
    )
  ) {
    return {
      ok: false,
      error:
        "Missing bearer token"
    };
  }

  try {
    const token =
      auth
        .slice(7)
        .trim();

    const secret =
      new TextEncoder().encode(
        env.JWT_SECRET
      );

    const {
      payload
    } = await jwtVerify(
      token,
      secret
    );

    return {
      ok: true,
      payload
    };
  } catch {
    return {
      ok: false,
      error:
        "Invalid token"
    };
  }
}

function parseEmailRaw(
  raw
) {
  return {
    headers: {
      subject:
        (
          raw.match(
            /^Subject:\s*(.*)$/im
          ) || []
        )[1] || ""
    },
    text:
      raw.split(
        /\r?\n\r?\n/
      )[1] || "",
    html: raw
  };
}

function createPreview(
  text
) {
  return String(
    text || ""
  )
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 120);
}

function randomString(
  length
) {
  const chars =
    "abcdefghijklmnopqrstuvwxyz0123456789";

  const bytes =
    new Uint8Array(
      length
    );

  crypto.getRandomValues(
    bytes
  );

  let out = "";

  for (const b of bytes) {
    out +=
      chars[
        b % chars.length
      ];
  }

  return out;
}

function getAllowedDomains(
  env
) {
  return String(
    env.DOMAINS || ""
  )
    .split(",")
    .map(x =>
      x.trim()
    )
    .filter(Boolean);
}

function json(
  data,
  status = 200
) {
  return new Response(
    JSON.stringify(
      data,
      null,
      2
    ),
    {
      status,
      headers: {
        "Content-Type":
          "application/json",
        "Access-Control-Allow-Origin":
          "*"
      }
    }
  );
}

function cors() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin":
        "*",
      "Access-Control-Allow-Headers":
        "*",
      "Access-Control-Allow-Methods":
        "*"
    }
  });
}
