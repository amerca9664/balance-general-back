import bcrypt from "bcrypt";
import type { Request, Response } from "express";
import {
	capSessions,
	clearRefreshCookie,
	getRefreshExpiry,
	handlePossibleReuse,
	hashRefreshToken,
	REFRESH_TOKEN_TTL_MS,
	SALT_ROUNDS,
	setRefreshCookie,
	signAccessToken,
	signRefreshToken,
	verifyRefreshToken,
} from "../helpers/authHelper.js";
import { RefreshTkModel } from "../models/refreshTkModel.js";
import { User } from "../models/users.js";

import { getRedisClient } from "../dbs/redis.js"; // Tu archivo anterior

const MAX_SESIONES = 5;

const insertarRefreshToken = async ({
	rt,
	userId,
	sessionId,
}: {
	rt: string;
	userId: string;
	sessionId: string;
}) => {
	const redis = getRedisClient();
	const tokenHash = hashRefreshToken(rt);

	// 1. Claves separadas para los datos y para el índice de sesiones
	const sessionDataKey = `session:${sessionId}`;
	const userSessionsSetKey = `user:${userId}:sessions`;

	const now = Date.now();
	const ttlInSeconds = REFRESH_TOKEN_TTL_MS / 1000;
	const expiracionTimestamp = now + REFRESH_TOKEN_TTL_MS;

	// MULTI inicia una transacción atómica en Redis
	const pipeline = redis.multi();

	// A. Guardamos el token real con su TTL individual exacto
	pipeline.set(sessionDataKey, tokenHash, "EX", ttlInSeconds);

	// B. Añadimos la sesión al set del usuario. El SCORE es el timestamp de cuándo va a expirar
	pipeline.zadd(userSessionsSetKey, expiracionTimestamp, sessionId);

	// C. LIMPIEZA AUTOMÁTICA: Borramos del Set del usuario las sesiones que YA expiraron en el tiempo
	pipeline.zremrangebyscore(userSessionsSetKey, "-inf", now);

	// D. CONTROL DE TOPE: Si quedan más de 5, eliminamos las más viejas (las que expiran antes, índices del 0 hacia arriba)
	// zremrangebyrank elimina por posición. Al indexar de 0 a -(MAX_SESIONES + 1), dejamos vivas solo las últimas 5 con mayor score
	pipeline.zremrangebyrank(userSessionsSetKey, 0, -(MAX_SESIONES + 1));

	// E. Renovamos el TTL del Set del usuario para que no quede huérfano si el usuario se vuelve inactivo
	pipeline.expire(userSessionsSetKey, ttlInSeconds);

	// Ejecutamos todo de un solo viaje al servidor Redis
	await pipeline.exec();

	console.log(
		`Refresh Token y sesión ${sessionId} gestionados para el usuario: ${userId}`,
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

			clearRefreshCookie(res);
		}

		const accessToken = signAccessToken(user._id, user.email);

		// Creamos la sesion primero para poder meter su _id en el JWT.
		// El tokenHash se completa abajo, cuando ya tenemos el token firmado.
		const session = await RefreshTkModel.create({
			idUser: user._id,
			tokenHash: "pending",
			expiresAt: getRefreshExpiry(),
		});

		const sessionId = crypto.randomUUID();

		const newRefreshToken = signRefreshToken(
			String(user._id),
			String(session._id),
			user.email,
			sessionId,
		);
		await insertarRefreshToken({
			rt: newRefreshToken,
			userId: String(user._id),
			sessionId,
		});
		await RefreshTkModel.updateOne(
			{ _id: session._id },
			{ tokenHash: hashRefreshToken(newRefreshToken) },
		);

		await capSessions(user._id);

		setRefreshCookie(res, newRefreshToken);

		return res
			.status(200)
			.json({ success: true, message: "ok", token: accessToken });
	} catch (_error) {
		console.error(_error);
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
		// Pasa por clearRefreshCookie y no por un literal: el `path` tiene que ser
		// identico al del setRefreshCookie() del final (los dos comparten
		// COOKIE_OPTIONS adentro del helper); si divergen, el clear no borra nada y
		// el token sigue viajando en cada request sin que se note.
		clearRefreshCookie(res);

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

		const decoded = verifyRefreshToken(cookieRefreshToken);
		if (!decoded) {
			// La sesion matcheo por hash pero el JWT no verifica: un doc vencido
			// cuyo TTL de Mongo ainda no corrio. Antes esto caia en el catch y
			// respondia 500; es un 403, el token simplemente ya no sirve.
			return res
				.status(403)
				.json({ success: false, message: "Refresh token inválido" });
		}

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

		const accessToken = signAccessToken(session.idUser, decoded.username);

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

		setRefreshCookie(res, newRefreshToken);

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
			// Antes esto no borraba nada: el token quedaba vivo hasta el TTL en la DB.
			await RefreshTkModel.deleteOne({
				tokenHash: hashRefreshToken(cookieRefreshToken),
			});
		}

		clearRefreshCookie(res);

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
