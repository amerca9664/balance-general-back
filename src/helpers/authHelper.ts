import { createHash } from "node:crypto";
import type { CookieOptions, Response } from "express";
import jwt from "jsonwebtoken";
import { getRedisClient } from "../dbs/redis.js";

export interface RefreshTokenPayload extends jwt.JwtPayload {
	id?: string;
	username?: string;
	/** Id de la sesion (familia de tokens) a la que pertenece este token. */
	sid?: string;
}

const IS_PRODUCTION = process.env.NODE_ENV === "production";

// Una sola fuente de verdad para setear Y limpiar la cookie.
// Si el path no coincide, clearCookie() no borra nada y el token
// sigue viajando en cada request.
const COOKIE_OPTIONS: CookieOptions = {
	httpOnly: true,
	secure: IS_PRODUCTION,
	sameSite: IS_PRODUCTION ? "none" : "lax",
	// Scoped al router de auth: no viaja en cada llamada a la API.
	path: "/api/auth",
};

/**
 * Lee una env var como entero positivo, con fallback.
 *
 * El ternario ingenuo (`env ? parseInt(env, 10) : fallback`) solo chequea
 * truthiness, asi que `"abc"` produce `NaN` (no cae al fallback) y `"0"`
 * produce `0`. Con `NaN`, `expiresIn` arma un JWT invalido y `jwt.sign`
 * lanza; con `0`, el token sale ya expirado y `MAX_SESSIONS 0` vacia todas
 * las sesiones en cada login. Un valor presente pero inutilizable tiene que
 * caer al default, no colarse.
 */
const readPositiveIntEnv = (name: string, fallback: number): number => {
	const raw = process.env[name];
	if (!raw) return fallback;
	const parsed = Number.parseInt(raw.trim(), 10);
	return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
};

const ACCESS_TOKEN_TTL_MINUTES = readPositiveIntEnv(
	"ACCESS_TOKEN_TTL_MINUTES",
	15,
);
const REFRESH_TOKEN_TTL_DAYS = readPositiveIntEnv("REFRESH_TOKEN_TTL_DAYS", 7);
export const REFRESH_TOKEN_TTL_MS =
	REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000;
const MAX_SESSIONS_PER_USER = readPositiveIntEnv("MAX_SESSIONS_PER_USER", 5);

// "Reuse interval" de Auth0 / "grace period" de Okta: cuantos segundos
// despues de una rotacion se sigue aceptando el token anterior.
//
// Cubre las requests concurrentes con la misma cookie (F5 repetidos, dos
// pestañas) y la respuesta perdida (F5 con el refresh en vuelo: el back rota
// pero el navegador nunca guarda el Set-Cookie). Dentro del intervalo se
// devuelve el token vigente; fuera, es reuso y se revoca esa sesion.
const REFRESH_REUSE_INTERVAL_SECONDS = readPositiveIntEnv(
	"REFRESH_REUSE_INTERVAL_SECONDS",
	30,
);

// bcrypt solo acepta 4..31 rounds: por debajo es debil, por encima lanza y
// rompe /register con un 500. El clamp evita que una env var mal escrita
// tire el registro de usuarios.
export const SALT_ROUNDS = Math.min(
	31,
	Math.max(4, readPositiveIntEnv("SALT_ROUNDS", 10)),
);

const sessionKey = (sid: string): string => `session:${sid}`;
const userSessionsKey = (userId: string): string => `user:${userId}:sessions`;
const ttlSeconds = (): number => REFRESH_TOKEN_TTL_MS / 1000;

/**
 * Hash DETERMINISTA a proposito.
 *
 * bcrypt no sirve aca: es salado, asi que no existe forma de armar
 * `WHERE tokenHash = ?` con el token crudo que llega en la cookie.
 * Solo podes hacer compare() contra un candidato que ya trajiste.
 *
 * SHA-256 si es determinista, asi que la busqueda es un lookup indexado.
 * No lleva sal a proposito: el token tiene ~250 bits de entropia,
 * no existe ataque de diccionario. La sal solo sirve para secretos
 * de baja entropia (passwords) y rompe justamente la propiedad
 * que nos permite buscar.
 */
export const hashRefreshToken = (rawToken: string): string =>
	createHash("sha256").update(rawToken).digest("hex");

/**
 * Firma un refresh token.
 *
 * El `jti` es lo que hace que cada rotacion produzca un token DISTINTO:
 * sin el, dos rotaciones dentro del mismo segundo generan el mismo payload
 * y por lo tanto la misma firma y el mismo hash.
 *
 * `iat` va explicito para que la firma sea reproducible: con los mismos
 * (userId, username, sid, jti, iat) HS256 da exactamente el mismo token. Asi
 * el reuse interval puede reenviar el token vigente sin guardarlo crudo en
 * Redis, solo su jti e iat.
 */
export const signRefreshToken = ({
	userId,
	username,
	sid,
	jti,
	iat,
}: {
	userId: string;
	username: string;
	sid: string;
	jti: string;
	iat: number;
}): string =>
	jwt.sign(
		{ id: userId, username, sid, jti, iat, exp: iat + ttlSeconds() },
		process.env.JWT_SECRET as string,
	);

/** Firma el access token de vida corta (ACCESS_TOKEN_TTL_MINUTES) que viaja en la response body. */
export const signAccessToken = (
	id: unknown,
	username: string | undefined,
): string =>
	jwt.sign({ id, username }, process.env.JWT_SECRET as string, {
		expiresIn: ACCESS_TOKEN_TTL_MINUTES * 60, // en segundos
	});

/**
 * Verifica firma y expiracion de un refresh token.
 * Devuelve `null` en vez de lanzar: quien llama decide que respuesta armar.
 */
export const verifyRefreshToken = (
	rawToken: string,
): RefreshTokenPayload | null => {
	try {
		return jwt.verify(rawToken, process.env.JWT_SECRET as string, {
			algorithms: ["HS256"],
		}) as RefreshTokenPayload;
	} catch {
		return null;
	}
};

export const setRefreshCookie = (res: Response, token: string): void => {
	res.cookie("jwt", token, {
		...COOKIE_OPTIONS,
		maxAge: REFRESH_TOKEN_TTL_MS,
		expires: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
	});
};

export const clearRefreshCookie = (res: Response): void => {
	res.clearCookie("jwt", COOKIE_OPTIONS);
	// Cookie `jti` de la version anterior: ya no se usa, se limpia para que
	// no quede huerfana en los navegadores que la tienen.
	res.clearCookie("jti", COOKIE_OPTIONS);
};

// ---------------------------------------------------------------------------
// Session store (Redis, unica fuente de verdad)
//
//   session:{sid}          HASH  userId, current, previous, rotatedAt,
//                                currentJti, currentIat     TTL = REFRESH_TOKEN_TTL
//   user:{userId}:sessions ZSET  member = sid   score = timestamp de expiracion
//
// Una sesion es una familia de refresh tokens: cada rotacion reemplaza
// `current` y deja el anterior en `previous`. Los tokens se guardan
// hasheados; `currentJti`/`currentIat` alcanzan para volver a firmar el
// vigente (ver signRefreshToken).
// ---------------------------------------------------------------------------

/**
 * Crea la sesion y la anota en el indice del usuario, en UNA sola llamada
 * Lua (todo o nada): purga del indice las sesiones vencidas y aplica el tope
 * de MAX_SESSIONS_PER_USER, borrando las que vencen antes.
 */
export const createSession = async ({
	userId,
	sid,
	tokenHash,
	jti,
	iat,
}: {
	userId: string;
	sid: string;
	tokenHash: string;
	jti: string;
	iat: number;
}): Promise<void> => {
	const redis = getRedisClient();
	const now = Date.now();

	await redis.eval(
		`
		redis.call("HSET", KEYS[1], "userId", ARGV[1], "current", ARGV[2],
			"previous", "", "rotatedAt", ARGV[3], "currentJti", ARGV[4],
			"currentIat", ARGV[5])
		redis.call("EXPIRE", KEYS[1], ARGV[6])
		redis.call("ZADD", KEYS[2], ARGV[7], ARGV[8])

		local expired = redis.call("ZRANGEBYSCORE", KEYS[2], "-inf", ARGV[3])
		for i = 1, #expired do
			redis.call("DEL", ARGV[10] .. expired[i])
			redis.call("ZREM", KEYS[2], expired[i])
		end

		local max = tonumber(ARGV[9])
		local total = redis.call("ZCARD", KEYS[2])
		if total > max then
			local doomed = redis.call("ZRANGE", KEYS[2], 0, total - max - 1)
			for i = 1, #doomed do
				redis.call("DEL", ARGV[10] .. doomed[i])
				redis.call("ZREM", KEYS[2], doomed[i])
			end
		end

		redis.call("EXPIRE", KEYS[2], ARGV[6])
		return 1
		`,
		2,
		sessionKey(sid),
		userSessionsKey(userId),
		userId,
		tokenHash,
		String(now),
		jti,
		String(iat),
		String(ttlSeconds()),
		String(now + REFRESH_TOKEN_TTL_MS),
		sid,
		MAX_SESSIONS_PER_USER,
		sessionKey(""),
	);

	console.log(`Sesión creada para el usuario: ${userId}`);
};

export type RefreshResult =
	| { status: "rotated" }
	| { status: "reused-in-interval"; jti: string; iat: number }
	| { status: "reuse-detected" }
	| { status: "not-found" };

/**
 * Rotacion con reuse interval, atomica en un solo script Lua:
 *
 *   - token == current  -> rota: previous = current, current = el nuevo.
 *   - token == previous y la rotacion fue hace <= REFRESH_REUSE_INTERVAL ->
 *     no rota; devuelve jti/iat del vigente para reenviarlo. De N requests
 *     concurrentes con la misma cookie, una rota y las demas caen aca, asi
 *     que todas terminan con el MISMO token.
 *   - cualquier otro token de la sesion -> reuso: se borra la sesion. Solo
 *     esa (la familia comprometida), no las demas sesiones del usuario.
 */
export const refreshSession = async ({
	userId,
	sid,
	tokenHash,
	nextHash,
	nextJti,
	nextIat,
}: {
	userId: string;
	sid: string;
	tokenHash: string;
	nextHash: string;
	nextJti: string;
	nextIat: number;
}): Promise<RefreshResult> => {
	const redis = getRedisClient();
	const now = Date.now();

	const result = (await redis.eval(
		`
		local s = redis.call("HMGET", KEYS[1], "userId", "current", "previous",
			"rotatedAt", "currentJti", "currentIat")
		if not s[1] or s[1] ~= ARGV[1] then
			return {"not-found"}
		end

		if s[2] == ARGV[2] then
			redis.call("HSET", KEYS[1], "previous", ARGV[2], "current", ARGV[3],
				"rotatedAt", ARGV[4], "currentJti", ARGV[5], "currentIat", ARGV[6])
			redis.call("EXPIRE", KEYS[1], ARGV[7])
			redis.call("ZADD", KEYS[2], ARGV[8], ARGV[9])
			redis.call("EXPIRE", KEYS[2], ARGV[7])
			return {"rotated"}
		end

		if s[3] == ARGV[2] and tonumber(ARGV[4]) - tonumber(s[4]) <= tonumber(ARGV[10]) then
			return {"reused-in-interval", s[5], s[6]}
		end

		redis.call("DEL", KEYS[1])
		redis.call("ZREM", KEYS[2], ARGV[9])
		return {"reuse-detected"}
		`,
		2,
		sessionKey(sid),
		userSessionsKey(userId),
		userId,
		tokenHash,
		nextHash,
		String(now),
		nextJti,
		String(nextIat),
		String(ttlSeconds()),
		String(now + REFRESH_TOKEN_TTL_MS),
		sid,
		String(REFRESH_REUSE_INTERVAL_SECONDS * 1000),
	)) as string[];

	const [status, jti, iat] = result;
	if (status === "reused-in-interval") {
		return { status, jti: jti as string, iat: Number(iat) };
	}
	return { status: status as "rotated" | "reuse-detected" | "not-found" };
};

/** Cierra una sesion puntual (logout). */
export const deleteSession = async (
	userId: string,
	sid: string,
): Promise<void> => {
	const redis = getRedisClient();
	await redis
		.multi()
		.del(sessionKey(sid))
		.zrem(userSessionsKey(userId), sid)
		.exec();
};

/**
 * Login con una cookie de refresh previa: cierra esa sesion vieja (si es del
 * mismo usuario que dice el token) para que no quede colgada. El resto de las
 * sesiones queda intacto.
 */
export const closePreviousSession = async (
	cookieRefreshToken: string,
): Promise<void> => {
	const prior = verifyRefreshToken(cookieRefreshToken);
	if (!prior?.id || !prior.sid) return;

	await deleteSession(prior.id, prior.sid);
	console.log("🔒 Sesión previa cerrada al iniciar sesión de nuevo.");
};
