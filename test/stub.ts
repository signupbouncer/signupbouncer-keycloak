// A stand-in for SignupBouncer's POST /v1/check, for test/e2e.sh. It answers by the email's local part:
//
//   allow...     a complete enforce-mode allow          block...    a complete block with STUB_MESSAGE
//   challenge... a complete challenge                   slow...     a block, but only after 3 seconds
//   error500...  HTTP 500                               junk...     HTTP 200 with a body that is not JSON
//   burstchallenge... a challenge with burst points      no email, IP 203.0.113.66: a block
//
// Any key other than "Bearer sb_live_e2e" gets 401 invalid_api_key, as the real API answers. GET /requests returns
// every request received (the key replaced by whether it matched), so the run can check what Keycloak sent.
//
//   deno run --allow-net=127.0.0.1:8097 test/stub.ts [port]

const port = Number(Deno.args[0] ?? 8097);
const KEY = "Bearer sb_live_e2e";
/** With an apostrophe, so the run shows Keycloak prints SignupBouncer's message as it was sent. */
export const STUB_MESSAGE = "Stub refusal: we don't take this address.";

interface Seen {
  keyOk: boolean;
  userAgent: string | null;
  body: unknown;
}
const seen: Seen[] = [];

function answer(action: "allow" | "challenge" | "block") {
  return {
    verdict: action,
    action,
    mode: "enforce",
    score: action === "allow" ? 0 : action === "challenge" ? 50 : 100,
    check_id: `chk_stub${seen.length}`,
    reasons: action === "allow" ? [] : [{ code: "disposable_domain", detail: "stub", points: 100, tier: "free" }],
    normalized: { provider: null, repeat_signups_7d: 0 },
    network: null,
    shadow: [],
    latency_ms: 1,
    quota_exceeded: false,
    ...(action === "allow" ? {} : { block_message: STUB_MESSAGE }),
  };
}

Deno.serve(
  { hostname: "127.0.0.1", port, onListen: () => console.log(`stub listening on 127.0.0.1:${port}`) },
  async (req) => {
    const url = new URL(req.url);
    if (req.method === "GET" && url.pathname === "/requests") return Response.json(seen);
    if (req.method !== "POST" || url.pathname !== "/v1/check") return new Response("not found", { status: 404 });
    const keyOk = req.headers.get("authorization") === KEY;
    let body: Record<string, unknown> = {};
    try {
      body = await req.json();
    } catch {
      // recorded as {}
    }
    seen.push({ keyOk, userAgent: req.headers.get("user-agent"), body });
    if (!keyOk) {
      return Response.json({ error: "invalid_api_key", message: "This API key is wrong." }, { status: 401 });
    }
    if (!body.email && body.ip === "203.0.113.66") return Response.json(answer("block"));
    const local = String(body.email ?? "").split("@")[0];
    if (local.startsWith("burstchallenge")) {
      const a = answer("challenge");
      a.reasons = [
        { code: "datacenter_ip", detail: "stub", points: 40, tier: "starter" },
        { code: "burst_subnet", detail: "stub", points: 25, tier: "pro" },
      ];
      return Response.json(a);
    }
    if (local.startsWith("allow")) return Response.json(answer("allow"));
    if (local.startsWith("block")) return Response.json(answer("block"));
    if (local.startsWith("challenge")) return Response.json(answer("challenge"));
    if (local.startsWith("slow")) {
      await new Promise((r) => setTimeout(r, 3000));
      return Response.json(answer("block"));
    }
    if (local.startsWith("error500")) return Response.json({ error: "internal" }, { status: 500 });
    if (local.startsWith("junk")) return new Response("<html>not json</html>", { status: 200 });
    return Response.json(answer("allow"));
  },
);
