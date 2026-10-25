import type { NextFunction, Request, Response } from "express";
import { RateLimiterRedis, RateLimiterRes } from "rate-limiter-flexible";
import { connectRedis } from "../dbs/redis.js";
import { getRequestMeta, readPositiveIntEnv } from "../helpers/authHelper.js";

// connectRedis y no getRedisClient: este modulo se importa (via las rutas)
// antes de que index.ts llame a connectRedis(), y es idempotente.
const storeClient = connectRedis();

// Fallos CONSECUTIVOS por email+IP: un login exitoso resetea el contador.
// duration/blockDuration van en segundos; las env vars, en minutos.
const byUserIp = new RateLimiterRedis({
	storeClient,
	keyPrefix: "login_fail_user_ip",
	points: readPositiveIntEnv("LOGIN_MAX_FAILS_PER_USER_IP", 5),
	duration: readPositiveIntEnv("LOGIN_USER_IP_WINDOW_MINUTES", 60) * 60,
	blockDuration: readPositiveIntEnv("LOGIN_USER_IP_BLOCK_MINUTES", 15) * 60,
});

// Tope por IP sola: frena a quien prueba muchos emails desde la misma IP.
const byIp = new RateLimiterRedis({
	storeClient,
	keyPrefix: "login_fail_ip",
	points: readPositiveIntEnv("LOGIN_MAX_FAILS_PER_IP", 100),
	duration: readPositiveIntEnv("LOGIN_IP_WINDOW_MINUTES", 24 * 60) * 60,
	blockDuration: readPositiveIntEnv("LOGIN_IP_BLOCK_MINUTES", 60) * 60,
});

/**
 * Consume un punto ANTES de llegar al controller, asi muchos requests en
 * paralelo no pasan todos el chequeo. Devuelve false si ya respondio (429/500).
 */
const tryConsume = async (
	limiter: RateLimiterRedis,
	key: string,
	res: Response,
	// El front lo usa para saber si cambiar de email desbloquea el boton.
	scope: "ip" | "user_ip",
): Promise<boolean> => {
	try {
		await limiter.consume(key);
		return true;
	} catch (error) {
		if (error instanceof RateLimiterRes) {
			const retryAfter = Math.ceil(error.msBeforeNext / 1000);
			res.set("Retry-After", String(retryAfter));
			res.status(429).json({
				success: false,
				message: "Demasiados intentos, intenta más tarde",
				scope,
				retryAfter,
			});
			return false;
		}
		console.error(error);
		res
			.status(500)
			.json({ success: false, message: "Error interno del servidor" });
		return false;
	}
};

/**
 * Rate limit de /login por IP. Va ANTES de `loginUserIpRateLimit`: asi los
 * reintentos de un email+IP ya bloqueado (429) tambien suman a la IP y no se
 * puede insistir con el mismo usuario gratis. Se devuelve el punto de todo lo
 * que no fue 401 ni 429 (exito, 409, 500).
 */
export const loginIpRateLimit = async (
	req: Request,
	res: Response,
	next: NextFunction,
): Promise<void> => {
	const ip = getRequestMeta(req).ip || "unknown";
	if (!(await tryConsume(byIp, ip, res, "ip"))) return;

	res.on("finish", () => {
		if (res.statusCode === 401 || res.statusCode === 429) return;
		byIp.reward(ip).catch(console.error);
	});

	next();
};

/**
 * Rate limit de /login por email+IP. Va despues de `validate(loginSchema)`:
 * necesita el email. Solo cuentan las credenciales invalidas (401); un login
 * exitoso borra el contador y el resto (409, 500) devuelve el punto.
 */
export const loginUserIpRateLimit = async (
	req: Request,
	res: Response,
	next: NextFunction,
): Promise<void> => {
	const ip = getRequestMeta(req).ip || "unknown";
	const key = `${String(req.body.email).trim().toLowerCase()}_${ip}`;
	if (!(await tryConsume(byUserIp, key, res, "user_ip"))) return;

	res.on("finish", () => {
		if (res.statusCode === 401) return;
		const restore =
			res.statusCode === 200 ? byUserIp.delete(key) : byUserIp.reward(key);
		restore.catch(console.error);
	});

	next();
};
