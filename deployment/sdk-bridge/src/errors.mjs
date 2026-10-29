// Sanitized error: only a fixed status and code leave the bridge, never provider prose or tokens.
export class BridgeError extends Error {
	constructor(status, code) {
		super(code);
		this.status = status;
		this.code = code;
	}
}
