import { BridgeError } from "./errors.mjs";

const MAX_USAGE_BODY = 128 * 1024;

function clampFraction(n) {
	if (typeof n !== "number" || !Number.isFinite(n)) return 0;
	return Math.max(0, Math.min(1, n));
}

function toRFC3339(val) {
	if (val === null || val === undefined || val === "") return null;
	if (typeof val === "number") {
		const ms = val > 1e12 ? val : val * 1000;
		if (!Number.isFinite(ms)) return null;
		return new Date(ms).toISOString();
	}
	if (typeof val === "string") {
		const d = new Date(val);
		if (Number.isNaN(d.getTime())) return null;
		return d.toISOString();
	}
	return null;
}

async function requestJson(url, init, fetchImpl) {
	let res;
	try {
		res = await fetchImpl(url, init);
	} catch (err) {
		if (err instanceof BridgeError) throw err;
		throw new BridgeError(502, "upstream_network_error");
	}

	if (!res.ok) {
		if (res.status === 429) {
			throw new BridgeError(429, "rate_limited");
		}
		if (res.status === 401 || res.status === 403) {
			throw new BridgeError(401, "unauthorized");
		}
		throw new BridgeError(502, "upstream_error");
	}

	const text = await res.text();
	if (text.length > MAX_USAGE_BODY) {
		throw new BridgeError(502, "response_too_large");
	}
	try {
		return JSON.parse(text);
	} catch {
		throw new BridgeError(502, "invalid_json");
	}
}

async function fetchAnthropicUsage(grant, fetchImpl) {
	const data = await requestJson(
		"https://api.anthropic.com/api/oauth/usage",
		{
			method: "GET",
			headers: {
				authorization: `Bearer ${grant.access}`,
				"anthropic-beta": "oauth-2025-04-20,claude-code-20250219",
				accept: "application/json",
				"user-agent": "anthropic-sdk-typescript/0.39.0 userOAuthProvider",
			},
		},
		fetchImpl,
	);

	const windows = [];
	if (data?.five_hour && typeof data.five_hour.utilization === "number") {
		const used = clampFraction(data.five_hour.utilization / 100);
		windows.push({
			id: "five_hour",
			label: "5-Hour Session",
			used_fraction: used,
			remaining_fraction: clampFraction(1 - used),
			resets_at: toRFC3339(data.five_hour.resets_at),
		});
	}
	if (data?.seven_day && typeof data.seven_day.utilization === "number") {
		const used = clampFraction(data.seven_day.utilization / 100);
		windows.push({
			id: "seven_day",
			label: "7-Day Weekly",
			used_fraction: used,
			remaining_fraction: clampFraction(1 - used),
			resets_at: toRFC3339(data.seven_day.resets_at),
		});
	}

	const plan = typeof data?.plan === "string" ? data.plan : null;
	return { plan, windows };
}

function normalizeCodexWindow(w, fallbackId, fallbackLabel) {
	if (!w || typeof w !== "object") return null;
	const usedPercent = typeof w.used_percent === "number" ? w.used_percent : 0;
	const used = clampFraction(usedPercent / 100);

	let id = fallbackId;
	let label = fallbackLabel;
	if (w.limit_window_seconds === 18000) {
		id = "five_hour";
		label = "5-Hour Session";
	} else if (w.limit_window_seconds === 604800) {
		id = "seven_day";
		label = "7-Day Weekly";
	} else if (typeof w.limit_window_seconds === "number") {
		if (w.limit_window_seconds >= 86400) {
			const d = Math.round(w.limit_window_seconds / 86400);
			id = `${d}d`;
			label = `${d}-Day Window`;
		} else {
			const h = Math.round(w.limit_window_seconds / 3600);
			id = `${h}h`;
			label = `${h}-Hour Window`;
		}
	}

	let resetsAt = null;
	if (typeof w.reset_at === "number") {
		resetsAt = toRFC3339(w.reset_at);
	} else if (typeof w.reset_after_seconds === "number") {
		resetsAt = new Date(Date.now() + w.reset_after_seconds * 1000).toISOString();
	}

	return {
		id,
		label,
		used_fraction: used,
		remaining_fraction: clampFraction(1 - used),
		resets_at: resetsAt,
	};
}

async function fetchCodexUsage(grant, fetchImpl) {
	const headers = {
		authorization: `Bearer ${grant.access}`,
		accept: "application/json",
		"user-agent": "codex-cli",
	};
	if (grant.accountId) {
		headers["ChatGPT-Account-Id"] = grant.accountId;
	}

	const data = await requestJson(
		"https://chatgpt.com/backend-api/wham/usage",
		{
			method: "GET",
			headers,
		},
		fetchImpl,
	);

	const windows = [];
	const rl = data?.rate_limit;
	if (rl?.primary_window) {
		const pw = normalizeCodexWindow(rl.primary_window, "five_hour", "5-Hour Session");
		if (pw) windows.push(pw);
	}
	if (rl?.secondary_window) {
		const sw = normalizeCodexWindow(rl.secondary_window, "seven_day", "7-Day Weekly");
		if (sw) windows.push(sw);
	}

	const plan = typeof data?.plan_type === "string" ? data.plan_type : null;
	return { plan, windows };
}

async function fetchAntigravityUsage(grant, fetchImpl) {
	let data;
	const body = JSON.stringify({ project: grant.projectId || "" });
	const headers = {
		authorization: `Bearer ${grant.access}`,
		"content-type": "application/json",
		"user-agent": "antigravity",
		"accept-encoding": "gzip",
	};

	try {
		data = await requestJson(
			"https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary",
			{ method: "POST", headers, body },
			fetchImpl,
		);
	} catch (err) {
		if (err instanceof BridgeError && (err.status === 404 || err.status === 501)) {
			data = await requestJson(
				"https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels",
				{ method: "POST", headers, body },
				fetchImpl,
			);
		} else {
			throw err;
		}
	}

	const rawBuckets = [];
	if (Array.isArray(data?.buckets)) {
		rawBuckets.push(...data.buckets);
	}
	if (Array.isArray(data?.groups)) {
		for (const g of data.groups) {
			if (Array.isArray(g?.buckets)) {
				rawBuckets.push(...g.buckets);
			}
		}
	}

	const windows = [];
	const seenIds = new Set();

	for (const b of rawBuckets) {
		if (b?.disabled === true) continue;
		const hint = `${b?.window ?? ""} ${b?.displayName ?? ""} ${b?.bucketId ?? ""}`.toLowerCase();
		let id = b?.bucketId || b?.window || "quota";
		let label = b?.displayName || b?.bucketId || "Quota";

		if (hint.includes("5h") || hint.includes("5 hour") || hint.includes("five_hour") || /5[\s_-]*hour/.test(hint)) {
			id = "five_hour";
			label = b?.displayName || "5-Hour Session";
		} else if (hint.includes("week") || hint.includes("7d") || hint.includes("7 day") || /7[\s_-]*day/.test(hint)) {
			id = "seven_day";
			label = b?.displayName || "7-Day Weekly";
		} else if (hint.includes("day") || hint.includes("daily") || hint.includes("24h")) {
			id = "daily";
			label = b?.displayName || "Daily Window";
		}

		if (seenIds.has(id)) continue;
		seenIds.add(id);

		let remaining = 1;
		if (typeof b?.remainingFraction === "number") {
			remaining = clampFraction(b.remainingFraction);
		} else if (typeof b?.remainingAmount === "number" && typeof b?.limit === "number" && b.limit > 0) {
			remaining = clampFraction(b.remainingAmount / b.limit);
		}
		const used = clampFraction(1 - remaining);

		windows.push({
			id,
			label,
			used_fraction: used,
			remaining_fraction: remaining,
			resets_at: toRFC3339(b?.resetTime),
		});
	}

	// Stable order: five_hour first, then seven_day, then others
	windows.sort((a, b) => {
		const order = { five_hour: 1, seven_day: 2, daily: 3 };
		return (order[a.id] ?? 99) - (order[b.id] ?? 99);
	});

	const plan = typeof data?.plan === "string" ? data.plan : null;
	return { plan, windows };
}

export async function fetchUsage({ provider, grant, fetchImpl = globalThis.fetch }) {
	let result;
	switch (provider) {
		case "anthropic":
			result = await fetchAnthropicUsage(grant, fetchImpl);
			break;
		case "openai-codex":
			result = await fetchCodexUsage(grant, fetchImpl);
			break;
		case "google-antigravity":
			result = await fetchAntigravityUsage(grant, fetchImpl);
			break;
		default:
			throw new BridgeError(400, "unsupported_provider");
	}

	return {
		provider,
		plan: result.plan ?? null,
		fetched_at: new Date().toISOString(),
		windows: result.windows,
	};
}
