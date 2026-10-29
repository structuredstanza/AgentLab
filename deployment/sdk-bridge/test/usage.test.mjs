import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createProfiles } from "../src/profiles.mjs";
import { createHandler } from "../src/server.mjs";

const SECRET_ACCESS = "super-secret-access-token-99999";
const SECRET_REFRESH = "super-secret-refresh-token-88888";

const fakeDriver = {
	async login(ctrl) {
		ctrl.onAuth({ url: "https://auth.example.invalid/start" });
		return {
			type: "oauth",
			access: SECRET_ACCESS,
			refresh: SECRET_REFRESH,
			expires: Date.now() + 3600000,
			email: "user@example.invalid",
			projectId: "test-project-123",
			accountId: "test-account-456",
		};
	},
	async refresh() {
		throw new Error("not used in fixture");
	},
	apiKey: grant => (grant.projectId ? JSON.stringify({ token: grant.access, projectId: grant.projectId }) : grant.access),
};

const authProviders = {
	anthropic: fakeDriver,
	"openai-codex": fakeDriver,
	"google-antigravity": fakeDriver,
};

const fakeSdk = {
	streamSimple() {
		throw new Error("not used in usage tests");
	},
	getBundledModels: () => [],
	getSupportedEfforts: () => [],
};

const TOKEN = "t".repeat(40);
let dataDir;
let handle;

const mockFetch = async (url, options = {}) => {
	const urlStr = String(url);
	if (urlStr.includes("api.anthropic.com/api/oauth/usage")) {
		return new Response(
			JSON.stringify({
				five_hour: { utilization: 25.0, resets_at: "2026-10-29T23:00:00Z" },
				seven_day: { utilization: 60.0, resets_at: "2026-11-05T00:00:00Z" },
			}),
			{ status: 200, headers: { "content-type": "application/json" } },
		);
	}

	if (urlStr.includes("chatgpt.com/backend-api/wham/usage")) {
		return new Response(
			JSON.stringify({
				plan_type: "pro",
				rate_limit: {
					primary_window: {
						used_percent: 15,
						limit_window_seconds: 18000,
						reset_at: 1793320000,
					},
					secondary_window: {
						used_percent: 40,
						limit_window_seconds: 604800,
						reset_at: 1793600000,
					},
				},
			}),
			{ status: 200, headers: { "content-type": "application/json" } },
		);
	}

	if (urlStr.includes("retrieveUserQuotaSummary")) {
		return new Response(
			JSON.stringify({
				buckets: [
					{
						bucketId: "gemini-5h",
						displayName: "5-Hour Session",
						window: "5h",
						remainingFraction: 0.75,
						resetTime: "2026-10-29T23:30:00Z",
					},
					{
						bucketId: "gemini-weekly",
						displayName: "Weekly Limit Remaining",
						window: "weekly",
						remainingFraction: 0.50,
						resetTime: "2026-11-05T12:00:00Z",
					},
				],
			}),
			{ status: 200, headers: { "content-type": "application/json" } },
		);
	}

	return new Response("Not Found", { status: 404 });
};

beforeEach(() => {
	dataDir = mkdtempSync(join(tmpdir(), "bridge-usage-test-"));
	const profiles = createProfiles({ dataDir, sdk: fakeSdk, authProviders, fetchImpl: mockFetch });
	handle = createHandler({ token: TOKEN, profiles });
});

afterEach(() => {
	rmSync(dataDir, { recursive: true, force: true });
});

const auth = { authorization: `Bearer ${TOKEN}` };
const req = (method, path, body, headers = auth) =>
	handle(
		new Request(`http://127.0.0.1:8788${path}`, {
			method,
			headers: body === undefined ? headers : { ...headers, "content-type": "application/json" },
			body: body === undefined ? undefined : JSON.stringify(body),
		}),
	);

const settle = () => Bun.sleep(10);

async function connectProfile(id, provider) {
	await req("POST", `/v1/profiles/${id}/login/start`, { provider });
	await settle();
}

describe("GET /v1/profiles/:id/usage", () => {
	test("returns 409 when disconnected", async () => {
		const res = await req("GET", "/v1/profiles/1/usage?provider=anthropic");
		expect(res.status).toBe(409);
		const body = await res.json();
		expect(body.error).toBe("not_connected");
	});

	test("normalizes 5h/7d windows for Anthropic and excludes secrets", async () => {
		await connectProfile("1", "anthropic");
		const res = await req("GET", "/v1/profiles/1/usage?provider=anthropic");
		expect(res.status).toBe(200);

		const text = await res.text();
		expect(text).not.toContain(SECRET_ACCESS);
		expect(text).not.toContain(SECRET_REFRESH);

		const body = JSON.parse(text);
		expect(body.provider).toBe("anthropic");
		expect(body.plan).toBeNull();
		expect(body.windows).toBeArray();
		expect(body.windows.length).toBe(2);

		const fiveHour = body.windows.find(w => w.id === "five_hour");
		expect(fiveHour).toBeDefined();
		expect(fiveHour.used_fraction).toBeCloseTo(0.25, 2);
		expect(fiveHour.remaining_fraction).toBeCloseTo(0.75, 2);
		expect(fiveHour.resets_at).toBe("2026-10-29T23:00:00.000Z");

		const sevenDay = body.windows.find(w => w.id === "seven_day");
		expect(sevenDay).toBeDefined();
		expect(sevenDay.used_fraction).toBeCloseTo(0.60, 2);
		expect(sevenDay.remaining_fraction).toBeCloseTo(0.40, 2);
		expect(sevenDay.resets_at).toBe("2026-11-05T00:00:00.000Z");
	});

	test("normalizes 5h/7d windows for OpenAI Codex and excludes secrets", async () => {
		await connectProfile("2", "openai-codex");
		const res = await req("GET", "/v1/profiles/2/usage?provider=openai-codex");
		expect(res.status).toBe(200);

		const text = await res.text();
		expect(text).not.toContain(SECRET_ACCESS);
		expect(text).not.toContain(SECRET_REFRESH);

		const body = JSON.parse(text);
		expect(body.provider).toBe("openai-codex");
		expect(body.plan).toBe("pro");
		expect(body.windows).toBeArray();
		expect(body.windows.length).toBe(2);

		const fiveHour = body.windows.find(w => w.id === "five_hour");
		expect(fiveHour).toBeDefined();
		expect(fiveHour.used_fraction).toBeCloseTo(0.15, 2);
		expect(fiveHour.remaining_fraction).toBeCloseTo(0.85, 2);

		const sevenDay = body.windows.find(w => w.id === "seven_day");
		expect(sevenDay).toBeDefined();
		expect(sevenDay.used_fraction).toBeCloseTo(0.40, 2);
		expect(sevenDay.remaining_fraction).toBeCloseTo(0.60, 2);
	});

	test("normalizes 5h/7d windows for Google Antigravity and excludes secrets", async () => {
		await connectProfile("3", "google-antigravity");
		const res = await req("GET", "/v1/profiles/3/usage?provider=google-antigravity");
		expect(res.status).toBe(200);

		const text = await res.text();
		expect(text).not.toContain(SECRET_ACCESS);
		expect(text).not.toContain(SECRET_REFRESH);

		const body = JSON.parse(text);
		expect(body.provider).toBe("google-antigravity");
		expect(body.windows).toBeArray();
		expect(body.windows.length).toBe(2);

		const fiveHour = body.windows.find(w => w.id === "five_hour");
		expect(fiveHour).toBeDefined();
		expect(fiveHour.used_fraction).toBeCloseTo(0.25, 2);
		expect(fiveHour.remaining_fraction).toBeCloseTo(0.75, 2);

		const sevenDay = body.windows.find(w => w.id === "seven_day");
		expect(sevenDay).toBeDefined();
		expect(sevenDay.used_fraction).toBeCloseTo(0.50, 2);
		expect(sevenDay.remaining_fraction).toBeCloseTo(0.50, 2);
	});
});
