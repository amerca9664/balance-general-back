import { randomUUID } from "node:crypto";
import bcrypt from "bcrypt";
import type { CookieOptions, Request, Response } from "express";
import jwt from "jsonwebtoken";
import type { Types } from "mongoose";
import {
	getRefreshExpiry,
	hashRefreshToken,
	MAX_SESSIONS_PER_USER,
	REFRESH_TOKEN_TTL_DAYS,
	RefreshTkModel,
} from "../models/refreshTkModel.js";
import { User } from "../models/users.js";

interface RefreshTokenPayload extends jwt.JwtPayload {
	id?: string;
	username?: string;
	sessionId?: string;
}

const SALT_ROUNDS = 10;
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
const signRefreshToken = (
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

/**
 * Tope de sesiones simultaneas por usuario.
 * Sin esto, un usuario que borra sus datos y vuelve a loguearse
 * acumula sesiones huerfanas hasta que el TTL las limpia (6 dias).
 */
const capSessions = async (idUser: Types.ObjectId): Promise<void> => {
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
const handlePossibleReuse = async (rawToken: string): Promise<void> => {
	let decoded: RefreshTokenPayload;
	try {
		decoded = jwt.verify(rawToken, process.env.JWT_SECRET as string, {
			algorithms: ["HS256"],
		}) as RefreshTokenPayload;
	} catch {
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

export const loginController = async (req: Request, res: Response) => {
	try {
		const { email, password } = req.body;
		const cookieRefreshToken = req.cookies?.jwt;

		const user = await User.findOne({ email });
		if (!user) {
			return res
				.status(401)
				.json({ success: false, message: "Credenciales inválidas" });
		}

		const isMatch = await bcrypt.compare(password, user.password);
		if (!isMatch) {
			return res
				.status(401)
				.json({ success: false, message: "Credenciales inválidas" });
		}

		if (cookieRefreshToken) {
			const existingSession = await RefreshTkModel.findOne({
				tokenHash: hashRefreshToken(cookieRefreshToken),
			});

			if (existingSession) {
				// 2) La cookie es tuya: rotamos solo esa sesion, el resto queda intacto.
				await RefreshTkModel.deleteOne({ _id: existingSession._id });
			} else {
				// 3) Cookie con token que no matchea ninguna sesion. Delega en el
				// handler: si el JWT verifica, el nuke es sobre el dueno del token
				// (que en el caso comun sos vos, asi que es un reset de tus
				// sesiones); si no verifica, no se toca nada. El login sigue igual.
				await handlePossibleReuse(cookieRefreshToken);
			}

			res.clearCookie("jwt", COOKIE_OPTIONS);
		}

		const accessToken = jwt.sign(
			{ id: user._id, username: user.email },
			process.env.JWT_SECRET as string,
			{ expiresIn: "1h" },
		);

		// Creamos la sesion primero para poder meter su _id en el JWT.
		// El tokenHash se completa abajo, cuando ya tenemos el token firmado.
		const session = await RefreshTkModel.create({
			idUser: user._id,
			tokenHash: "pending",
			expiresAt: getRefreshExpiry(),
		});

		const newRefreshToken = signRefreshToken(
			String(user._id),
			String(session._id),
			user.email,
		);

		await RefreshTkModel.updateOne(
			{ _id: session._id },
			{ tokenHash: hashRefreshToken(newRefreshToken) },
		);

		await capSessions(user._id);

		res.cookie("jwt", newRefreshToken, {
			...COOKIE_OPTIONS,
			maxAge: REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000,
		});

		return res
			.status(200)
			.json({ success: true, message: "ok", token: accessToken });
	} catch (_error) {
		return res
			.status(500)
			.json({ success: false, message: "Error interno del servidor" });
	}
};

export const registerController = async (req: Request, res: Response) => {
	try {
		const { username, email, password } = req.body;

		const existingUser = await User.findOne({ email });
		if (existingUser) {
			return res
				.status(409)
				.json({ success: false, message: "El email ya está registrado" });
		}

		const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

		const newUser = await User.create({
			username,
			email,
			password: hashedPassword,
		});

		return res.status(201).json({
			success: true,
			message: "Usuario registrado",
			data: { id: newUser._id },
		});
	} catch (_error) {
		return res
			.status(500)
			.json({ success: false, message: "Error interno del servidor" });
	}
};

export const handleRefreshToken = async (req: Request, res: Response) => {
	try {
		const cookieRefreshToken = req.cookies?.jwt;
		if (!cookieRefreshToken) {
			return res
				.status(401)
				.json({ success: false, message: "Falta refresh token" });
		}

		// Uncondicional, como en el original: garantiza que ninguna salida de esta
		// funcion deje viva una cookie vieja, incluidas las de error y el 500.
		// Usa COOKIE_OPTIONS y no un literal porque el `path` tiene que ser identico
		// al del res.cookie() del final; si divergen, el clear no borra nada y el
		// token sigue viajando en cada request sin que se note.
		res.clearCookie("jwt", COOKIE_OPTIONS);

		const session = await RefreshTkModel.findOne({
			tokenHash: hashRefreshToken(cookieRefreshToken),
		});

		if (!session) {
			await handlePossibleReuse(cookieRefreshToken);
			return res
				.status(403)
				.json({ success: false, message: "Refresh token inválido" });
		}

		// TTL de Mongo corre cada ~60s, asi que puede quedar un doc vencido
		// un rato. Lo borramos aca para no dejarlo huerfano.
		if (session.expiresAt.getTime() < Date.now()) {
			await RefreshTkModel.deleteOne({ _id: session._id });
			return res
				.status(403)
				.json({ success: false, message: "Refresh token expirado" });
		}

		const decoded = jwt.verify(
			cookieRefreshToken,
			process.env.JWT_SECRET as string,
			{ algorithms: ["HS256"] },
		) as RefreshTokenPayload;

		if (!decoded.id || String(session.idUser) !== decoded.id) {
			// El token verifica con firma valida pero pertenece a otro usuario
			// que la sesion encontrada por hash: es una reinyeccion. Misma
			// politica que el reuse: se revocan todas las sesiones del dueno
			// del token presentado.
			console.log("🚨 ¡Refresh token de otro usuario detectado!");
			await RefreshTkModel.deleteMany({
				idUser: decoded.id ?? session.idUser,
			});
			return res
				.status(403)
				.json({ success: false, message: "Refresh token manipulado" });
		}

		const accessToken = jwt.sign(
			{ id: session.idUser, username: decoded.username },
			process.env.JWT_SECRET as string,
			{ expiresIn: "1h" },
		);

		// Rotacion in-place: el _id no cambia, asi que el sessionId del access
		// token sigue siendo valido y el token viejo deja de matchear el hash.
		const newRefreshToken = signRefreshToken(
			String(session.idUser),
			String(session._id),
			String(decoded.username),
		);

		// El filtro incluye el hash VIEJO a proposito (compare-and-set). Filtrar
		// solo por _id dejaba que dos requests concurrentes sobre la misma cookie
		// escribieran las dos: la segunda machacaba el tokenHash de la primera y
		// esa cookie quedaba muerta en el navegador. Su proximo refresh era un
		// 403 -> handlePossibleReuse -> nuke-all de todas las sesiones. Con el
		// hash viejo en el filtro solo uno gana; el otro ve modifiedCount 0 y se
		// trata como reuse, que es lo que realmente es.
		const previousHash = hashRefreshToken(cookieRefreshToken);
		const rotation = await RefreshTkModel.updateOne(
			{ _id: session._id, tokenHash: previousHash },
			{
				tokenHash: hashRefreshToken(newRefreshToken),
				createdAt: new Date(),
				expiresAt: getRefreshExpiry(),
			},
		);

		if (rotation.modifiedCount === 0) {
			// Perdio la carrera el CAS. NO es robo y por eso NO se nukea: el hash
			// presentado matcheo hace un instante, asi que el token era valido y lo
			// unico que paso es que otro request del MISMO cliente lo rotó primero
			// (doble pestaña, retry, o el intervalo del front). Nuke-all aca te
			// desloguearia de todos tus dispositivos por una carrera propia.
			//
			// Un token realmente robado nunca llega aca: fallaria antes, en el
			// findOne por tokenHash, que es donde vive la deteccion de robo.
			//
			// Tampoco se borra la cookie: la respuesta perdedora puede llegar
			// DESPUES de la ganadora, y su Set-Cookie de borrado pisaria el token
			// bueno que acaba de emitir el ganador.
			console.log(
				"Rotación perdida: otro request del mismo cliente ya rotó esto.",
			);
			return res
				.status(403)
				.json({ success: false, message: "Refresh token ya rotado" });
		}

		res.cookie("jwt", newRefreshToken, {
			...COOKIE_OPTIONS,
			maxAge: REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000,
		});

		return res
			.status(200)
			.json({ success: true, message: "ok", token: accessToken });
	} catch (_error) {
		return res
			.status(500)
			.json({ success: false, message: "Error interno del servidor" });
	}
};

export const logoutController = async (req: Request, res: Response) => {
	try {
		const cookieRefreshToken = req.cookies?.jwt;
		if (cookieRefreshToken) {
			// Antes esto no borraba nada: el token quedaba vivo 6 dias en la DB.
			await RefreshTkModel.deleteOne({
				tokenHash: hashRefreshToken(cookieRefreshToken),
			});
		}

		res.clearCookie("jwt", COOKIE_OPTIONS);

		return res
			.status(200)
			.json({ success: true, message: "Sesión cerrada correctamente" });
	} catch (_error) {
		return res
			.status(500)
			.json({ success: false, message: "Error interno del servidor" });
	}
};

// Ruta protegida: verifyToken ya corrió, asi que req.user existe.
export const meController = (req: Request, res: Response) => {
	if (!req.user) {
		return res.status(401).json({ success: false, message: "No autenticado" });
	}

	return res.status(200).json({ success: true, data: req.user });
};
