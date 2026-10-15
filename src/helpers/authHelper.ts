import { createHash, randomUUID } from "node:crypto";
import type { CookieOptions, Response } from "express";
import jwt from "jsonwebtoken";
import { getRedisClient } from "../dbs/redis.js";

export interface RefreshTokenPayload extends jwt.JwtPayload {
	id?: string;
	username?: string;
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

// Ventana en la que un token recien rotado todavia se acepta como "doble
// disparo del mismo cliente" en vez de tratarse como robo. Corta a proposito:
// durante esos segundos, presentar un token ya rotado devuelve un access token
// nuevo en vez de nukear. Trade-off deliberado contra el falso positivo del
// doble-fire (dos refresh en paralelo con la misma cookie).
const ROTATION_GRACE_SECONDS = readPositiveIntEnv("ROTATION_GRACE_SECONDS", 15);
// Tope de saltos al seguir la cadena `rtr:` en rotaciones encadenadas
// (3+ refresh simultaneos). Evita un loop si la cadena quedara corrupta.
const MAX_ROTATION_GRACE_HOPS = 5;

// bcrypt solo acepta 4..31 rounds: por debajo es debil, por encima lanza y
// rompe /register con un 500. El clamp evita que una env var mal escrita
// tire el registro de usuarios.
export const SALT_ROUNDS = Math.min(
	31,
	Math.max(4, readPositiveIntEnv("SALT_ROUNDS", 10)),
);

const rtKey = (tokenHash: string): string => `rt:${tokenHash}`;
const userSessionsKey = (userId: string): string => `user:${userId}:sessions`;
// Marca de rotacion reciente: hashViejo -> hashNuevo, con TTL corto. Es lo que
// permite reconocer el doble-fire que llega DESPUES del ganador.
const recentRotationKey = (tokenHash: string): string => `rtr:${tokenHash}`;
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
 * (id/username/iat/exp iguales) y por lo tanto la misma firma y el mismo
 * hash, con lo cual el token "viejo" seguiria matcheando y la rotacion no
 * cortaria nada.
 */
export const signRefreshToken = (userId: string, username: string): string =>
	jwt.sign(
		{ id: userId, username, jti: randomUUID() },
		process.env.JWT_SECRET as string,
		// Template literal explicito: `REFRESH_TOKEN_TTL_DAYS + "d"` se
		// ensancha a `string` y @types/jsonwebtoken v9 exige el tipo
		// `${number}d`.
		{ expiresIn: `${REFRESH_TOKEN_TTL_DAYS}d` },
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
};

// ---------------------------------------------------------------------------
// Session store (Redis, unica fuente de verdad)
//
//   rt:{sha256(token)}     STRING  value = userId      TTL = REFRESH_TOKEN_TTL
//   user:{userId}:sessions ZSET    member = tokenHash   score = timestamp de expiracion
//
// El indice va por el HASH DEL TOKEN, no por un id de sesion: es la traduccion
// directa del `findOne({ tokenHash })` que tenia Mongo. Quien llega con la
// cookie trae el token, asi que con hashearla ya sabe donde buscar y no hace
// falta que el JWT cargue ninguna sesion.
// ---------------------------------------------------------------------------

/**
 * Ubica al dueno del token. `null` = ese token ya no existe: o nunca lo
 * emitimos, o ya fue rotado. Es el lookup que decide reuse.
 */
export const getSessionByHash = async (
	tokenHash: string,
): Promise<string | null> => {
	const redis = getRedisClient();
	return redis.get(rtKey(tokenHash));
};

/**
 * Crea la sesion y la anota en el indice del usuario, en UNA sola llamada
 * Lua (todo o nada):
 *
 *   - `SET ... EX` por clave: el token muere solo en el instante exacto en
 *     que vence, sin el desfasaje de ~60s que tiene el TTL collector de Mongo.
 *   - `ZRANGEBYSCORE -inf now`: saca del indice los tokens ya vencidos y
 *     tambien sus claves `rt:`, que vencieron junto con ellos.
 *   - `ZRANGE 0 total-max-1`: tope de sesiones simultaneas, dejando vivas las
 *     `MAX` que vencen mas tarde.
 *   - `EXPIRE` sobre el set: si el usuario queda inactivo el indice no queda
 *     como huerfano.
 *
 * Los `DEL` de los tokens expulsados van dentro del mismo script que los
 * `ZREM`, no aparte. Si se separaran, el tope quedaria con un hueco: la clave
 * `rt:` del token expulsado seguira viva, asi que ese token sigue pudiendo
 * refrescar, y como la rotacion vuelve a hacer `ZADD` en el indice, el tope
 * no limita nada con el tiempo. Peor: `deleteAllSessions` lee el ZSET, asi
 * que un token expulsado pero no borrado sobrevive a un nuke.
 *
 * El miembro nuevo se agrega ANTES de purgar y topar: su score es el mas alto
 * de todos, asi que nunca queda dentro del rango expulsado.
 */
export const createSession = async ({
	userId,
	tokenHash,
}: {
	userId: string;
	tokenHash: string;
}): Promise<void> => {
	const redis = getRedisClient();
	const now = Date.now();

	await redis.eval(
		`
		redis.call("SET", KEYS[1], ARGV[1], "EX", ARGV[2])
		redis.call("ZADD", KEYS[2], ARGV[3], ARGV[4])

		local expired = redis.call("ZRANGEBYSCORE", KEYS[2], "-inf", ARGV[5])
		for i = 1, #expired do
			redis.call("DEL", ARGV[7] .. expired[i])
			redis.call("ZREM", KEYS[2], expired[i])
		end

		local max = tonumber(ARGV[6])
		local total = redis.call("ZCARD", KEYS[2])
		if total > max then
			local doomed = redis.call("ZRANGE", KEYS[2], 0, total - max - 1)
			for i = 1, #doomed do
				redis.call("DEL", ARGV[7] .. doomed[i])
				redis.call("ZREM", KEYS[2], doomed[i])
			end
		end

		redis.call("EXPIRE", KEYS[2], ARGV[2])
		return 1
		`,
		2,
		rtKey(tokenHash),
		userSessionsKey(userId),
		userId,
		String(ttlSeconds()),
		String(now + REFRESH_TOKEN_TTL_MS),
		tokenHash,
		String(now),
		MAX_SESSIONS_PER_USER,
		rtKey(""),
	);

	console.log(`Sesión creada para el usuario: ${userId}`);
};

/**
 * Rotacion con compare-and-set atomico.
 *
 * El `GET == userId` (pertenenecia), el `DEL` del token viejo y el `SET` del
 * nuevo van dentro del MISMO script Lua, asi que son indivisibles: de dos
 * requests concurrentes con la misma cookie, UNA sola recibe 1. La otra
 * devuelve 0 y responde 403 sin nukear, porque haber encontrado el token hace
 * un instante prueba que era valido y lo unico que paso es que otro request
 * del mismo cliente lo roto primero (doble pestaña, retry, o el intervalo del
 * front).
 *
 * SIN este CAS, la segunda escritura dejaria el token viejo vivo y esa cookie
 * quedaria valida para siempre.
 *
 * El token realmente robado nunca llega aca: falla antes, en
 * `getSessionByHash`, que es donde vive la deteccion de robo.
 */
export const rotateSession = async ({
	userId,
	previousHash,
	nextHash,
}: {
	userId: string;
	previousHash: string;
	nextHash: string;
}): Promise<boolean> => {
	const redis = getRedisClient();

	const result = await redis.eval(
		`
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			redis.call("DEL", KEYS[1])
			redis.call("SET", KEYS[2], ARGV[1], "EX", ARGV[2])
			redis.call("ZREM", KEYS[3], ARGV[3])
			redis.call("ZADD", KEYS[3], ARGV[4], ARGV[5])
			redis.call("EXPIRE", KEYS[3], ARGV[2])
			redis.call("SET", KEYS[4], ARGV[5], "EX", ARGV[6])
			return 1
		end
		return 0
		`,
		4,
		rtKey(previousHash),
		rtKey(nextHash),
		userSessionsKey(userId),
		recentRotationKey(previousHash),
		userId,
		String(ttlSeconds()),
		previousHash,
		String(Date.now() + REFRESH_TOKEN_TTL_MS),
		nextHash,
		String(ROTATION_GRACE_SECONDS),
	);

	return result === 1;
};

/**
 * Resuelve si un token que ya no esta en `rt:` fue rotado hace instantes por el
 * MISMO usuario. Sigue la cadena `rtr:` (hashViejo -> hashNuevo) hasta topar con
 * una sesion viva del usuario:
 *
 *   - `rt:{next}` devuelve el userId  -> rotacion legitima, hay gracia.
 *   - `rt:{next}` no existe           -> ese token tambien se rotó; seguir el
 *                                        siguiente eslabon.
 *   - `rt:{next}` es de OTRO usuario   -> manipulacion; sin gracia (se nukea).
 *
 * Devuelve `false` si no hay marca o si la cadena no lleva a una sesion del
 * usuario: eso deja el camino libre al nuke de reuse.
 */
export const resolveRecentRotation = async (
	previousHash: string,
	userId: string,
): Promise<boolean> => {
	const redis = getRedisClient();
	let current = previousHash;

	for (let hop = 0; hop < MAX_ROTATION_GRACE_HOPS; hop++) {
		const nextHash = await redis.get(recentRotationKey(current));
		if (!nextHash) return false;

		const owner = await getSessionByHash(nextHash);
		if (owner === userId) return true;
		if (owner !== null) return false;

		current = nextHash;
	}

	return false;
};

export const deleteSessionByHash = async (
	userId: string,
	tokenHash: string,
): Promise<void> => {
	const redis = getRedisClient();
	await redis
		.multi()
		.del(rtKey(tokenHash))
		.zrem(userSessionsKey(userId), tokenHash)
		.exec();
};

/**
 * Revoca TODOS los tokens del usuario. Sale del ZSET y no de un escaneo:
 * los miembros del set se limpian solos por score cada vez que se escribe, y
 * el set nunca vence antes que sus claves (su TTL se renueva en cada
 * escritura, asi que siempre >= el del token mas nuevo).
 */
export const deleteAllSessions = async (userId: string): Promise<void> => {
	const redis = getRedisClient();
	const key = userSessionsKey(userId);
	const tokenHashes = await redis.zrange(key, "0", "-1");

	const pipeline = redis.multi();
	for (const hash of tokenHashes) {
		pipeline.del(rtKey(hash));
	}
	pipeline.del(key);
	await pipeline.exec();
};

/**
 * Reuse detection. La usan /login y /refresh, y la respuesta NO es la misma:
 *
 *   /refresh  -> 403. No hay password, solo el token, asi que la victima
 *                es el dueno del token y se le cortan todas sus sesiones.
 *   /login    -> 200. La password ya autentico a `user`, asi que el login
 *                continua: el nuke es un reset defensivo y despues se crea
 *                la sesion nueva de ese mismo usuario.
 *
 * En ambos casos el nuke es sobre `decoded.id` (dueno del token), NO sobre
 * quien esta autenticado. En el caso comun de login, la cookie vieja es del
 * mismo usuario que se esta autenticando, asi que `decoded.id === user._id`
 * y el efecto es reset + login limpio.
 *
 * El `await` con que loginController lo invoca es a proposito: sin esto el
 * delete corre en paralelo al create de la sesion nueva y puede borrarla.
 *
 * Si el JWT ni siquiera verifica (firma invalida, otro secret, expirado) no
 * se toca nada, porque no hay a quien atribuirle el token. Eso cubre tambien
 * la cookie basura: nunca dispara un nuke. Y cubre el vencimiento normal:
 * cuando la clave ya no existe, el JWT firmado en el mismo momento tampoco
 * verifica, asi que no se revoca nada.
 *
 * OJO, vector conocido: si la cookie trae un token valido de OTRO usuario, el
 * nuke cae sobre las sesiones de ese otro. Quien tenga tu cookie puede llamar
 * a /login con credenciales propias y borrarte las sesiones sin tu password.
 * Cerrarlo exige comparar `decoded.id` contra el usuario autenticado.
 */
export const handlePossibleReuse = async (rawToken: string): Promise<void> => {
	const decoded = verifyRefreshToken(rawToken);

	if (!decoded) {
		// Firma invalida o expirado: no se puede atribuir a ningun usuario.
		console.log("Refresh token expirado o manipulado.");
		return;
	}

	if (!decoded.id) return;

	console.log("🚨 ¡Intento de reutilización de Refresh Token detectado!");
	await deleteAllSessions(decoded.id);
	console.log(
		`🔒 Todas las sesiones invalidadas para: ${decoded.username ?? decoded.id}.`,
	);
};

export const existingLoginTokenReuseLogic = async (
	cookieRefreshToken: string,
) => {
	const prior = verifyRefreshToken(cookieRefreshToken);

	if (!prior?.id) {
		console.log("🚨 ¡Refresh token inválido detectado!");
		return;
	}

	const priorHash = hashRefreshToken(cookieRefreshToken);
	const priorUserId = await getSessionByHash(priorHash);

	if (priorUserId === prior.id) {
		// 2) La cookie es tuya: cerramos solo esa sesion, el resto queda intacto.
		await deleteSessionByHash(priorUserId, priorHash);

		console.log(
			"🔒 Sesión previa cerrada: el refresh token presentado ya estaba en uso.",
		);

		return;
	}
	// console.log("🚨 ¡Intento de reutilización de Refresh Token detectado!");
	// await deleteAllSessions(prior.id);
	// console.log(
	// 	`🔒 Todas las sesiones invalidadas para: ${prior.username ?? prior.id}.`,
	// );
};
