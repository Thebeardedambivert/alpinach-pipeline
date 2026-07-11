// 04 approval-handler — Supabase Edge Function (edge-runtime v1.71.x, Deno)
//
// Public, unauthenticated endpoint. The approval token IS the credential —
// there is no login. Served under /functions/v1/approval.
//
// Routes:
//   GET  /approval/approve?token=...  -> confirmation page. NO state change.
//   POST /approval/approve            -> redeem token, hand posts to 05.
//   GET  /approval/reject?token=...   -> reject form (regenerate | cancel).
//   POST /approval/reject             -> record the rejection.
//
// Safety properties (each one load-bearing):
//   * GET NEVER mutates. Outlook Safe Links, corporate scanners and antivirus
//     gateways GET every URL in an inbound email before the human sees it. An
//     approve-on-GET would publish everything the instant the mail arrives.
//     Only POST acts.
//   * Identical response for invalid / expired / already-used tokens. The DB
//     functions already return empty on all three; we must not distinguish
//     them either, or we confirm to an attacker which tokens were once real.
//   * Referrer-Policy: no-referrer (header + meta). The token is in the query
//     string; without this it leaks via Referer. No external assets are loaded.
//   * Rate limiting on POST only, by IP, via check_approval_rate_limit.
//   * The raw token is NEVER written to a log line.

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_KEY =
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ??
  Deno.env.get("SERVICE_ROLE_KEY") ??
  Deno.env.get("SERVICE_KEY") ??
  "";
// Set once 05 exists. Until then, approvals succeed but nothing publishes.
const PUBLISH_WEBHOOK_URL = Deno.env.get("PUBLISH_WEBHOOK_URL") ?? "";

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RL_MAX = 10;
const RL_WINDOW_MIN = 10;

// ---- HTML -------------------------------------------------------------------
function shell(title: string, inner: string): string {
  return `<!doctype html><html lang="de"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${title}</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;background:#f4f4f5;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1a1a1a}
  .wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .card{background:#fff;max-width:520px;width:100%;border:1px solid #e5e5e5;border-radius:12px;padding:32px}
  h1{font-size:20px;margin:0 0 12px}
  p{font-size:15px;line-height:1.55;color:#444;margin:0 0 16px}
  .btn{display:inline-block;border:none;cursor:pointer;font-size:15px;font-weight:600;padding:14px 28px;border-radius:8px;text-decoration:none}
  .btn-primary{background:#111;color:#fff}
  .muted{font-size:13px;color:#8a8a8a}
  label{font-size:14px}
  textarea{width:100%;border:1px solid #d4d4d8;border-radius:8px;padding:10px;min-height:80px;font-family:inherit;font-size:14px}
  fieldset{border:1px solid #e5e5e5;border-radius:8px;margin:0 0 16px;padding:12px 16px}
  .row{margin:8px 0}
</style></head><body><div class="wrap"><div class="card">${inner}</div></div></body></html>`;
}

function htmlResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Referrer-Policy": "no-referrer",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

const pageInvalid = () =>
  shell(
    "Link nicht gueltig",
    `<h1>Link nicht g\u00fcltig</h1>
     <p>Dieser Link ist nicht mehr g\u00fcltig, abgelaufen oder wurde bereits verwendet.</p>
     <p class="muted">Bei Fragen wenden Sie sich bitte an Ihren Ansprechpartner.</p>`,
  );

const pageRateLimited = () =>
  shell(
    "Zu viele Versuche",
    `<h1>Zu viele Versuche</h1>
     <p>Von dieser Verbindung wurden zu viele Anfragen gestellt. Bitte versuchen Sie es in einigen Minuten erneut.</p>`,
  );

const pageError = () =>
  shell(
    "Fehler",
    `<h1>Etwas ist schiefgelaufen</h1>
     <p>Bitte versuchen Sie es sp\u00e4ter erneut.</p>`,
  );

const pageConfirmApprove = (token: string) =>
  shell(
    "Captions freigeben",
    `<h1>Captions freigeben</h1>
     <p>Mit der Freigabe werden Ihre Captions zur Ver\u00f6ffentlichung freigegeben. Bitte best\u00e4tigen Sie.</p>
     <form method="POST" action="">
       <input type="hidden" name="token" value="${token}">
       <button class="btn btn-primary" type="submit">Freigeben</button>
     </form>
     <p class="muted" style="margin-top:16px">Wenn Sie das nicht angefordert haben, schliessen Sie diese Seite einfach.</p>`,
  );

const pageApproved = (n: number) =>
  shell(
    "Freigegeben",
    `<h1>Freigegeben</h1>
     <p>Ihre ${n} Caption${n === 1 ? "" : "s"} ${n === 1 ? "wurde" : "wurden"} freigegeben und ${n === 1 ? "wird" : "werden"} nun ver\u00f6ffentlicht.</p>
     <p class="muted">Sie k\u00f6nnen diese Seite jetzt schliessen.</p>`,
  );

const pageRejectForm = (token: string) =>
  shell(
    "Captions ablehnen",
    `<h1>Captions ablehnen</h1>
     <p>M\u00f6chten Sie neue Captions erstellen lassen oder den Vorgang abbrechen?</p>
     <form method="POST" action="">
       <input type="hidden" name="token" value="${token}">
       <fieldset>
         <div class="row"><label><input type="radio" name="action" value="regenerate" checked> Neue Captions erstellen lassen</label></div>
         <div class="row"><label><input type="radio" name="action" value="cancel"> Vorgang abbrechen</label></div>
       </fieldset>
       <label for="reason">Grund (optional)</label>
       <textarea id="reason" name="reason" maxlength="1000"></textarea>
       <div style="margin-top:16px"><button class="btn btn-primary" type="submit">Absenden</button></div>
     </form>`,
  );

const pageRejected = (action: string) =>
  action === "regenerate"
    ? shell(
      "Ueberarbeitung angefordert",
      `<h1>\u00dcberarbeitung angefordert</h1>
       <p>Es werden neue Captions erstellt. Sie erhalten in K\u00fcrze eine neue E-Mail zur Freigabe.</p>
       <p class="muted">Sie k\u00f6nnen diese Seite jetzt schliessen.</p>`,
    )
    : shell(
      "Vorgang abgebrochen",
      `<h1>Vorgang abgebrochen</h1>
       <p>Es werden keine Beitr\u00e4ge ver\u00f6ffentlicht.</p>
       <p class="muted">Sie k\u00f6nnen diese Seite jetzt schliessen.</p>`,
    );

// ---- helpers ----------------------------------------------------------------
function clientIp(req: Request): string {
  const xff = req.headers.get("x-forwarded-for");
  if (xff) return xff.split(",")[0].trim();
  return req.headers.get("x-real-ip") ?? "";
}

async function rpc(fn: string, body: Record<string, unknown>): Promise<unknown> {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${fn}`, {
    method: "POST",
    headers: {
      "apikey": SERVICE_KEY,
      "Authorization": `Bearer ${SERVICE_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`rpc ${fn} -> ${res.status}: ${text.slice(0, 200)}`);
  }
  return await res.json();
}

async function withinRateLimit(ip: string, endpoint: string): Promise<boolean> {
  const allowed = await rpc("check_approval_rate_limit", {
    p_ip: ip,
    p_endpoint: endpoint,
    p_max: RL_MAX,
    p_window_minutes: RL_WINDOW_MIN,
  });
  return allowed === true;
}

async function readToken(
  req: Request,
  url: URL,
): Promise<{ token: string; form: FormData | null }> {
  if (req.method === "POST") {
    let form: FormData | null = null;
    try {
      form = await req.formData();
    } catch {
      form = null;
    }
    const t = String(form?.get("token") ?? "") ||
      (url.searchParams.get("token") ?? "");
    return { token: t.trim(), form };
  }
  return { token: (url.searchParams.get("token") ?? "").trim(), form: null };
}

// ---- main -------------------------------------------------------------------
Deno.serve(async (req: Request) => {
  try {
    if (!SUPABASE_URL || !SERVICE_KEY) {
      console.error("approval: missing SUPABASE_URL or service key env");
      return htmlResponse(pageError(), 500);
    }

    const url = new URL(req.url);
    const parts = url.pathname.split("/").filter(Boolean); // ['approval','approve']
    const action = parts[1] ?? "";
    const method = req.method;

    if (action !== "approve" && action !== "reject") {
      return htmlResponse(pageInvalid(), 404);
    }

    const { token, form } = await readToken(req, url);
    const tokenValid = UUID_RE.test(token);

    // GET: render only. Token validity is NOT checked here, so a prefetch or
    // scan learns nothing and — critically — changes nothing.
    if (method === "GET") {
      if (!tokenValid) return htmlResponse(pageInvalid());
      return htmlResponse(
        action === "approve" ? pageConfirmApprove(token) : pageRejectForm(token),
      );
    }

    // POST: the acting path. Rate-limit BEFORE anything else so garbage
    // sprays count against the attacker too.
    if (method === "POST") {
      const ip = clientIp(req);
      if (!(await withinRateLimit(ip, action))) {
        return htmlResponse(pageRateLimited(), 429);
      }
      if (!tokenValid) return htmlResponse(pageInvalid());

      if (action === "approve") {
        const posts = await rpc("redeem_approval_token", {
          p_token: token,
          p_ip: ip,
        });
        if (!Array.isArray(posts) || posts.length === 0) {
          return htmlResponse(pageInvalid()); // invalid/expired/used — identical
        }
        // Hand approved posts to 05. Best-effort: they are ALREADY marked
        // 'approved' in the DB, so a trigger failure must not fail the agent's
        // approval. Until 05 exists, PUBLISH_WEBHOOK_URL is unset -> skip.
        if (PUBLISH_WEBHOOK_URL) {
          try {
            await fetch(PUBLISH_WEBHOOK_URL, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              // deno-lint-ignore no-explicit-any
              body: JSON.stringify({ post_ids: posts.map((p: any) => p.post_id) }),
            });
          } catch (e) {
            console.error("approval: publish webhook failed", String(e).slice(0, 120));
          }
        }
        return htmlResponse(pageApproved(posts.length));
      }

      // action === 'reject'
      const rawAction = String(form?.get("action") ?? "");
      const rejAction =
        rawAction === "regenerate" || rawAction === "cancel" ? rawAction : "";
      const reason = String(form?.get("reason") ?? "").slice(0, 1000);
      if (!rejAction) return htmlResponse(pageInvalid());

      const result = await rpc("reject_approval_token", {
        p_token: token,
        p_action: rejAction,
        p_reason: reason || null,
        p_ip: ip,
      });
      if (!result) return htmlResponse(pageInvalid());
      return htmlResponse(pageRejected(rejAction));
    }

    return htmlResponse(pageInvalid(), 405);
  } catch (e) {
    console.error("approval: unhandled", String(e).slice(0, 200));
    return htmlResponse(pageError(), 500);
  }
});
