import { test } from "node:test";
import assert from "node:assert/strict";
import { redactor } from "../src/profiles.mjs";

test("redacts raw and JSON-escaped OAuth secrets, including overlapping and quoted values", () => {
	const access = 'sk-ant-oat-AB"c\\d';
	const refresh = "rt_refresh\nvalue";
	const apiKey = JSON.stringify({ access, refresh });
	const redact = redactor([access, refresh, apiKey]);

	const sdkError = `upstream echoed ${access} and ${JSON.stringify(refresh)} and ${apiKey}`;
	const out = redact(JSON.stringify({ type: "error", error: sdkError }));

	for (const secret of [access, refresh, apiKey, JSON.stringify(access).slice(1, -1), JSON.stringify(refresh).slice(1, -1)]) {
		assert.ok(!out.includes(secret), "secret must not survive redaction");
	}
	assert.ok(out.includes("[redacted]"));
});

test("leaves unrelated strings such as project ids untouched", () => {
	const redact = redactor(["sk-ant-oat-secret-value"]);
	const project = "projects/12345-project";
	assert.equal(redact(`{"project":"${project}"}`), `{"project":"${project}"}`);
});

test("ignores empty secrets instead of masking every position", () => {
	const redact = redactor(["", "token-value"]);
	assert.equal(redact("a token-value b"), "a [redacted] b");
});
