const TURNSTILE_VERIFY_URL =
	"https://challenges.cloudflare.com/turnstile/v0/siteverify";

// El `cf-turnstile-response` tiene un tope razonable; si llega mas largo es
// basura y ni vale la pena mandarlo a Cloudflare.
const MAX_TOKEN_LENGTH = 2048;
const TURNSTILE_TIMEOUT_MS = 10_000;

interface SiteverifyResult {
	success?: boolean;
	action?: string;
	hostname?: string;
	"error-codes"?: string[];
}

/**
 * Allowlist de hostnames del frontend. Se lee del env como CSV y se normaliza
 * a minusculas. Un valor vacio deja el set vacio, lo que corta toda validacion
 * (fail-closed): sin allowlist no hay forma de confiar en el `hostname` que
 * devuelve siteverify.
 */
const readHostnameAllowlist = (): Set<string> =>
	new Set(
		(process.env.TURNSTILE_HOSTNAMES ?? "")
			.split(",")
			.map((hostname) => hostname.trim().toLowerCase())
			.filter(Boolean),
	);

export interface VerifyTurnstileParams {
	token: unknown;
	remoteip?: string | undefined;
	expectedAction: string;
}

/**
 * Validacion server-side canonica contra siteverify.
 *
 * Gate, no replace: devuelve `true` solo si Cloudflare confirma el token y
 * ademas el `action` y el `hostname` coinciden con lo esperado. Cualquier
 * excepcion (timeout, red, JSON roto) devuelve `false`.
 */
export const verifyTurnstileToken = async ({
	token,
	remoteip,
	expectedAction,
}: VerifyTurnstileParams): Promise<boolean> => {
	const expectedHostnames = readHostnameAllowlist();
	const secret = process.env.TURNSTILE_SECRET;

	if (
		typeof token !== "string" ||
		token.length === 0 ||
		token.length > MAX_TOKEN_LENGTH ||
		!secret ||
		expectedHostnames.size === 0
	) {
		return false;
	}

	let result: SiteverifyResult;
	try {
		const body = new URLSearchParams({ secret, response: token });
		if (remoteip) body.set("remoteip", remoteip);

		const response = await fetch(TURNSTILE_VERIFY_URL, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			signal: AbortSignal.timeout(TURNSTILE_TIMEOUT_MS),
			body,
		});

		if (!response.ok) {
			throw new Error(`siteverify devolvio ${response.status}`);
		}

		result = (await response.json()) as SiteverifyResult;
	} catch (error) {
		console.error("Turnstile siteverify fallo:", error);
		return false;
	}

	return (
		result.success === true &&
		result.action === expectedAction &&
		typeof result.hostname === "string" &&
		expectedHostnames.has(result.hostname.toLowerCase())
	);
};
