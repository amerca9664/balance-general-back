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
 * Rate limit de /login. Va despues de `validate(loginSchema)`: necesita el email.
 *
 * Cada intento consume ANTES de llegar al controller, asi muchos requests en
 * paralelo no pasan todos el chequeo. Al terminar la respuesta se devuelven los
 * puntos de todo lo que no fue 401 (exito, 409, 500): solo cuentan las
 * credenciales invalidas.
 */
export const loginRateLimit = async (
	req: Request,
	res: Response,
	next: NextFunction,
): Promise<void> => {
	const ip = getRequestMeta(req).ip || "unknown";
	const userIpKey = `${String(req.body.email).trim().toLowerCase()}_${ip}`;

	try {
		await Promise.all([byUserIp.consume(userIpKey), byIp.consume(ip)]);
	} catch (error) {
		if (error instanceof RateLimiterRes) {
			res.set("Retry-After", String(Math.ceil(error.msBeforeNext / 1000)));
			res.status(429).json({
				success: false,
				message: "Demasiados intentos, intenta más tarde",
			});
			return;
		}
		console.error(error);
		res
			.status(500)
			.json({ success: false, message: "Error interno del servidor" });
		return;
	}

	res.on("finish", () => {
		if (res.statusCode === 401) return;
		const restore =
			res.statusCode === 200
				? byUserIp.delete(userIpKey)
				: byUserIp.reward(userIpKey);
		Promise.all([restore, byIp.reward(ip)]).catch(console.error);
	});

	next();
};
