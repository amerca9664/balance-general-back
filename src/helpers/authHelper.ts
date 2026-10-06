import { randomUUID } from "node:crypto";
import type { CookieOptions, Response } from "express";
import jwt from "jsonwebtoken";
import type { Types } from "mongoose";
import {
	MAX_SESSIONS_PER_USER,
	REFRESH_TOKEN_TTL_DAYS,
	REFRESH_TOKEN_TTL_MS,
	RefreshTkModel,
} from "../models/refreshTkModel.js";

export interface RefreshTokenPayload extends jwt.JwtPayload {
	id?: string;
	username?: string;
	sessionId?: string;
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
 * Firma un refresh token.
 *
 * El `jti` es lo que hace que cada rotacion produzca un token DISTINTO:
 * sin el, dos rotaciones dentro del mismo segundo generan el mismo payload
 * (id/username/sessionId/iat/exp iguales) y por lo tanto la misma firma, con
 * lo cual el token "viejo" seguiria siendo valido y la rotacion no cortaria
 * nada.
 */
export const signRefreshToken = (
	userId: string,
	sessionId: string,
	username: string,
): string =>
	jwt.sign(
		{ id: userId, username, sessionId, jti: randomUUID() },
		process.env.JWT_SECRET as string,
		// Template literal explicito: `6 + "d"` se ensancha a `string` y
		// @types/jsonwebtoken v9 exige el tipo `${number}d`.
		{ expiresIn: `${REFRESH_TOKEN_TTL_DAYS}d` },
	);

/** Firma el access token de vida corta (1h) que viaja en la response body. */
export const signAccessToken = (
	id: unknown,
	username: string | undefined,
): string =>
	jwt.sign({ id, username }, process.env.JWT_SECRET as string, {
		expiresIn: "1h",
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

/**
 * Tope de sesiones simultaneas por usuario.
 * Sin esto, un usuario que borra sus datos y vuelve a loguearse
 * acumula sesiones huerfanas hasta que el TTL las limpia (6 dias).
 */
export const capSessions = async (idUser: Types.ObjectId): Promise<void> => {
	const total = await RefreshTkModel.countDocuments({ idUser });
	if (total <= MAX_SESSIONS_PER_USER) return;

	const oldest = await RefreshTkModel.find({ idUser })
		.sort({ createdAt: 1 })
		.limit(total - MAX_SESSIONS_PER_USER)
		.select("_id");

	await RefreshTkModel.deleteMany({
		_id: { $in: oldest.map((session) => session._id) },
	});
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
 * deleteMany corre en paralelo al create de la sesion nueva y puede borrarla.
 *
 * Si el JWT ni siquiera verifica (firma invalida, otro secret, expirado) no
 * se toca nada, porque no hay a quien atribuirle el token. Eso cubre tambien
 * la cookie basura: nunca dispara un nuke.
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
	await RefreshTkModel.deleteMany({ idUser: decoded.id });
	console.log(
		`🔒 Todas las sesiones invalidadas para: ${decoded.username ?? decoded.id}.`,
	);
};
