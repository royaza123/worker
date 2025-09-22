const ALLOWED_EVENTS = [
  "whatsapp_join",
  "messenger_join",
  "video_play",
  "video_play_lesson5",
  "ml_email_ready",
];

const TTL_BY_EVENT = {
  whatsapp_join: 60 * 60 * 24 * 30,       // 30d
  messenger_join: 60 * 60 * 24 * 30,      // 30d
  video_play: 60 * 60 * 12,               // 12h per lesson
  video_play_lesson5: 60 * 60 * 12,       // 12h
  ml_email_ready: 60 * 60 * 23,           // 23h
};

const N8N_URL = "https://aetophisn8n.app.n8n.cloud/webhook/gtm-intake";
const SHARED_SECRET = "roy-gtm-2025";

// add any additional domains you serve the pages from
const ALLOWED_ORIGINS = new Set([
  "https://eproformula.com",
  "https://www.eproformula.com",
  "https://aetophis.com",
  "https://www.aetophis.com",
]);

export default {
  async fetch(request, env, ctx) {
    // CORS preflight
    if (request.method === "OPTIONS") {
      return cors(null, 204, request);
    }

    const { pathname } = new URL(request.url);
    if (request.method !== "POST" || (pathname !== "/ingest" && pathname !== "/beacon")) {
      return cors(new Response("Not found", { status: 404 }), 404, request);
    }

    const origin = request.headers.get("Origin");
    const referer = request.headers.get("Referer");
    const allowByOrigin = origin && ALLOWED_ORIGINS.has(origin);
    const allowByReferer = referer && safeHostOk(referer);

    // Require a known Origin or Referer to cut random spam
    if (!allowByOrigin && !allowByReferer) {
      return cors(new Response("Forbidden", { status: 403 }), 403, request);
    }

    // Read body: JSON on /ingest, text on /beacon
    let body;
    try {
      if (pathname === "/ingest") {
        body = await request.json();
      } else {
        const txt = await request.text();
        body = JSON.parse(txt || "{}");
      }
    } catch {
      return cors(new Response("Bad body", { status: 400 }), 400, request);
    }

    // Security: shared secret
    if (body?.secret !== SHARED_SECRET) {
      return cors(new Response("Forbidden", { status: 403 }), 403, request);
    }

    // Validate event + shape
    const event = String(body.event || "");
    if (!ALLOWED_EVENTS.includes(event)) {
      return cors(new Response("Invalid event", { status: 400 }), 400, request);
    }

    const email = normalizeEmail(body.email);
    const lesson = body.lesson ? String(body.lesson) : ""; // empty for non-lesson events
    const ts = Number(body.ts || Date.now());

    // Build an idempotency key: event+email(+lesson)
    const keyRaw = [event, email, event.startsWith("video") ? lesson : ""].join("|");
    const keyHash = await sha256Hex(keyRaw);
    const cacheKey = `https://dedupe.epro/cache/${keyHash}`;
    const ttl = TTL_BY_EVENT[event] || 3600;

    // server-side de-dup via Cloudflare cache
    const cache = caches.default;
    const cacheReq = new Request(cacheKey, { method: "GET" });

    const cached = await cache.match(cacheReq);
    if (cached) {
      // Already seen within TTL → pretend success (cheap)
      return cors(json({ ok: true, deduped: true }), 200, request);
    }

    // Store the key before forwarding (best-effort)
    const stamp = new Response("ok", {
      headers: { "Cache-Control": `public, max-age=${ttl}` },
    });
    await cache.put(cacheReq, stamp);

    // Forward to n8n with retries + HMAC signature
    const payload = { event, email, lesson, progress: body.progress ?? null, ts, secret: SHARED_SECRET };
    const sig = await hmacHex(JSON.stringify(payload), SHARED_SECRET);

    const init = {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Epro-Idempotency-Key": keyHash,
        "X-Epro-Signature": sig,
      },
      body: JSON.stringify(payload),
    };

    const success = await postWithRetry(N8N_URL, init, [0, 300, 1000, 2000]);

    // If n8n failed hard, we still keep the cache stamp to avoid hammering.
    // You’ll see it in n8n "Executions" if it got through.
    return cors(json({ ok: !!success, deduped: false }), success ? 200 : 202, request);
  },
};

/* ---------- utils ---------- */

function cors(res, _status, request) {
  const origin = request.headers.get("Origin");
  const allowOrigin = ALLOWED_ORIGINS.has(origin || "") ? origin : "*";
  const headers = {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
  };
  if (!res) return new Response(null, { status: 204, headers });
  for (const [k, v] of Object.entries(headers)) res.headers.set(k, v);
  return res;
}

function json(obj) {
  return new Response(JSON.stringify(obj), { headers: { "Content-Type": "application/json" } });
}

function normalizeEmail(e) {
  return String(e || "").trim().toLowerCase();
}

function safeHostOk(referer) {
  try {
    const u = new URL(referer);
    const h = `https://${u.hostname}`;
    return ALLOWED_ORIGINS.has(h);
  } catch {
    return false;
  }
}

async function postWithRetry(url, init, delays) {
  for (let i = 0; i < delays.length; i++) {
    if (delays[i]) await new Promise(r => setTimeout(r, delays[i]));
    try {
      const res = await fetch(url, init);
      if (res.ok) return true;
      // retry on 5xx, 429
      if (res.status >= 500 || res.status === 429) continue;
      return false;
    } catch {
      // network error → retry
      continue;
    }
  }
  return false;
}

async function sha256Hex(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hmacHex(message, secret) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}
