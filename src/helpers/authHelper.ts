import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { CookieOptions, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { getRedisClient } from "../dbs/redis.js";

const IS_PRODUCTION = process.env.NODE_ENV === "production";

// Una sola fuente de verdad para setear Y limpiar la cookie.
// Si el path no coincide, clearCookie() no borra nada y el token
// sigue viajando en cada request.
const COOKIE_OPTIONS: CookieOptions = {
	httpOnly: true,
	secure: IS_PRODUCTION,
	sameSite: IS_PRODUCTION ? "strict" : "lax",
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
export const readPositiveIntEnv = (name: string, fallback: number): number => {
	const raw = process.env[name];
	if (!raw) return fallback;
	const parsed = Number.parseInt(raw.trim(), 10);
	return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
};

const ACCESS_TOKEN_TTL_MINUTES = readPositiveIntEnv(
	"ACCESS_TOKEN_TTL_MINUTES",
	15,
);
// Vencimiento por INACTIVIDAD: cada /refresh lo vuelve a extender.
const REFRESH_TOKEN_TTL_DAYS = readPositiveIntEnv("REFRESH_TOKEN_TTL_DAYS", 7);
export const REFRESH_TOKEN_TTL_MS =
	REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000;
// Vida maxima ABSOLUTA de una sesion, aunque se use todos los dias. Acota
// cuanto sirve una cookie robada: como el token no rota, este tope y el
// logout son las formas de matarla.
const SESSION_MAX_AGE_DAYS = readPositiveIntEnv("SESSION_MAX_AGE_DAYS", 30);
const SESSION_MAX_AGE_MS = SESSION_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;
const MAX_SESSIONS_PER_USER = readPositiveIntEnv("MAX_SESSIONS_PER_USER", 5);

// bcrypt solo acepta 4..31 rounds: por debajo es debil, por encima lanza y
// rompe /register con un 500. El clamp evita que una env var mal escrita
// tire el registro de usuarios.
export const SALT_ROUNDS = Math.min(
	31,
	Math.max(4, readPositiveIntEnv("SALT_ROUNDS", 10)),
);

const sessionKey = (tokenHash: string): string => `session:${tokenHash}`;
const userSessionsKey = (userId: string): string => `user:${userId}:sessions`;
const ttlSeconds = (): number => REFRESH_TOKEN_TTL_MS / 1000;

/**
 * Token de sesion opaco: 32 bytes aleatorios, sin significado propio. Todo lo
 * que hace falta saber de la sesion vive en Redis.
 *
 * No rota: el mismo token sirve toda la vida de la sesion. Asi no existen
 * carreras entre refresh concurrentes (F5 repetidos, varias pestañas, una
 * respuesta perdida o un 429 en el medio): todas las requests mandan el mismo
 * token y todas reciben lo mismo.
 */
export const generateSessionToken = (): string =>
	randomBytes(32).toString("base64url");

/**
 * Hash DETERMINISTA a proposito.
 *
 * bcrypt no sirve aca: es salado, asi que no existe forma de armar
 * `WHERE tokenHash = ?` con el token crudo que llega en la cookie.
 * Solo podes hacer compare() contra un candidato que ya trajiste.
 *
 * SHA-256 si es determinista, asi que la busqueda es un lookup indexado.
 * No lleva sal a proposito: el token tiene 256 bits de entropia,
 * no existe ataque de diccionario. La sal solo sirve para secretos
 * de baja entropia (passwords) y rompe justamente la propiedad
 * que nos permite buscar.
 */
export const hashSessionToken = (rawToken: string): string =>
	createHash("sha256").update(rawToken).digest("hex");

/** Firma el access token de vida corta (ACCESS_TOKEN_TTL_MINUTES) que viaja en la response body. */
export const signAccessToken = (
	id: unknown,
	username: string | undefined,
	roles: string[],
): string =>
	jwt.sign({ id, username, roles }, process.env.JWT_SECRET as string, {
		expiresIn: ACCESS_TOKEN_TTL_MINUTES * 60, // en segundos
	});

export const setSessionCookie = (res: Response, token: string): void => {
	res.cookie("jwt", token, {
		...COOKIE_OPTIONS,
		maxAge: REFRESH_TOKEN_TTL_MS,
		expires: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
	});
};

export const clearSessionCookie = (res: Response): void => {
	res.clearCookie("jwt", COOKIE_OPTIONS);
	// Cookie `jti` de versiones anteriores: ya no se usa, se limpia para que
	// no quede huerfana en los navegadores que la tienen.
	res.clearCookie("jti", COOKIE_OPTIONS);
};

// ---------------------------------------------------------------------------
// Session store (Redis, unica fuente de verdad)
//
//   session:{sha256(token)} HASH  userId, username, createdAt, id,
//                                 userAgent, ip, country,
//                                 lastSeenAt, lastIp, lastCountry   TTL = inactividad
//   user:{userId}:sessions  ZSET  member = tokenHash   score = timestamp de expiracion
//
// El token se guarda hasheado: quien lea Redis no puede usar las sesiones.
//
// `id` es el identificador PUBLICO de la sesion (para listarla o cerrarla
// desde el front): nunca se expone el hash del token. Los metadatos de origen
// (userAgent/ip/country) son del login; los `last*` se actualizan en cada
// refresh. Viven lo mismo que la sesion: la IP es dato personal y no se
// guarda mas alla de eso.
// ---------------------------------------------------------------------------

/** De donde viene una request: lo que se anota en la sesion. */
export interface RequestMeta {
	userAgent: string;
	ip: string;
	country: string;
}

// Un User-Agent puede medir lo que el cliente quiera: se recorta para que no
// infle Redis.
const MAX_USER_AGENT_LENGTH = 512;

/**
 * Extrae user-agent, IP y pais de la request.
 *
 * `CF-Connecting-IP` y `CF-IPCountry` los agrega Cloudflare (tambien en el
 * plan gratuito; el pais requiere activar IP Geolocation en Network). Solo son
 * confiables si al origen no se puede llegar sin pasar por Cloudflare: si se
 * puede, cualquiera los inventa. Sin Cloudflare (local) cae a la IP del
 * socket y el pais queda vacio.
 */
export const getRequestMeta = (req: Request): RequestMeta => {
	const cfIp = req.get("cf-connecting-ip");
	return {
		userAgent: (req.get("user-agent") ?? "").slice(0, MAX_USER_AGENT_LENGTH),
		ip: cfIp ?? req.socket.remoteAddress ?? "",
		country: req.get("cf-ipcountry") ?? "",
	};
};

/**
 * Crea la sesion y la anota en el indice del usuario, en UNA sola llamada
 * Lua (todo o nada): purga del indice las sesiones vencidas y aplica el tope
 * de MAX_SESSIONS_PER_USER, borrando las que vencen antes.
 */
export const createSession = async ({
	userId,
	username,
	tokenHash,
	meta,
}: {
	userId: string;
	username: string;
	tokenHash: string;
	meta: RequestMeta;
}): Promise<void> => {
	const redis = getRedisClient();
	const now = Date.now();

	await redis.eval(
		`
		redis.call("HSET", KEYS[1], "userId", ARGV[1], "username", ARGV[2],
			"createdAt", ARGV[3], "id", ARGV[9], "userAgent", ARGV[10], "ip", ARGV[11],
			"country", ARGV[12], "lastSeenAt", ARGV[3], "lastIp", ARGV[11],
			"lastCountry", ARGV[12])
		redis.call("EXPIRE", KEYS[1], ARGV[4])
		redis.call("ZADD", KEYS[2], ARGV[5], ARGV[6])

		local expired = redis.call("ZRANGEBYSCORE", KEYS[2], "-inf", ARGV[3])
		for i = 1, #expired do
			redis.call("DEL", ARGV[8] .. expired[i])
			redis.call("ZREM", KEYS[2], expired[i])
		end

		local max = tonumber(ARGV[7])
		local total = redis.call("ZCARD", KEYS[2])
		if total > max then
			local doomed = redis.call("ZRANGE", KEYS[2], 0, total - max - 1)
			for i = 1, #doomed do
				redis.call("DEL", ARGV[8] .. doomed[i])
				redis.call("ZREM", KEYS[2], doomed[i])
			end
		end

		redis.call("EXPIRE", KEYS[2], ARGV[4])
		return 1
		`,
		2,
		sessionKey(tokenHash),
		userSessionsKey(userId),
		userId,
		username,
		String(now),
		String(ttlSeconds()),
		String(now + REFRESH_TOKEN_TTL_MS),
		tokenHash,
		MAX_SESSIONS_PER_USER,
		sessionKey(""),
		randomUUID(),
		meta.userAgent,
		meta.ip,
		meta.country,
	);

	console.log(`Sesión creada para el usuario: ${userId}`);
};

export interface Session {
	userId: string;
	username: string;
}

/**
 * Busca la sesion del token y, si sigue valida, extiende su vencimiento por
 * inactividad (sliding expiration) y anota desde donde se uso por ultima vez.
 * Pasada la vida maxima absoluta la borra.
 * Todo en un solo script: dos refresh concurrentes ven lo mismo.
 *
 * `null` = no hay sesion: nunca existio, vencio, se cerro o llego al tope.
 */
export const touchSession = async (
	tokenHash: string,
	meta: RequestMeta,
): Promise<Session | null> => {
	const redis = getRedisClient();
	const now = Date.now();

	const result = (await redis.eval(
		`
		local s = redis.call("HMGET", KEYS[1], "userId", "username", "createdAt")
		if not s[1] then
			return nil
		end

		local index = ARGV[5] .. s[1] .. ":sessions"
		if tonumber(ARGV[1]) - tonumber(s[3]) > tonumber(ARGV[2]) then
			redis.call("DEL", KEYS[1])
			redis.call("ZREM", index, ARGV[6])
			return nil
		end

		redis.call("HSET", KEYS[1], "lastSeenAt", ARGV[1], "lastIp", ARGV[7],
			"lastCountry", ARGV[8])
		redis.call("EXPIRE", KEYS[1], ARGV[3])
		redis.call("ZADD", index, ARGV[4], ARGV[6])
		redis.call("EXPIRE", index, ARGV[3])
		return {s[1], s[2]}
		`,
		1,
		sessionKey(tokenHash),
		String(now),
		String(SESSION_MAX_AGE_MS),
		String(ttlSeconds()),
		String(now + REFRESH_TOKEN_TTL_MS),
		"user:",
		tokenHash,
		meta.ip,
		meta.country,
	)) as [string, string] | null;

	if (!result) return null;
	const [userId, username] = result;
	return { userId, username };
};

/** Cierra una sesion puntual (logout, o login con una cookie previa). */
export const deleteSession = async (tokenHash: string): Promise<void> => {
	const redis = getRedisClient();
	const userId = await redis.hget(sessionKey(tokenHash), "userId");

	const pipeline = redis.multi().del(sessionKey(tokenHash));
	if (userId) pipeline.zrem(userSessionsKey(userId), tokenHash);
	await pipeline.exec();
};
