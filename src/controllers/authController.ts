import bcrypt from "bcrypt";
import type { Request, Response } from "express";
import {
	clearRefreshCookie,
	createSession,
	deleteAllSessions,
	deleteSessionByHash,
	existingLoginTokenReuseLogic,
	getSessionByHash,
	handlePossibleReuse,
	hashRefreshToken,
	rotateSession,
	SALT_ROUNDS,
	setRefreshCookie,
	signAccessToken,
	signRefreshToken,
	verifyRefreshToken,
} from "../helpers/authHelper.js";
import { User } from "../models/users.js";

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
			// La busqueda es por el hash de la cookie: no hace falta confiar en
			// nada que diga el JWT para saber si esa sesion existe.
			await existingLoginTokenReuseLogic(cookieRefreshToken);
			clearRefreshCookie(res);
		}

		const accessToken = signAccessToken(user._id, user.email);

		const newRefreshToken = signRefreshToken(String(user._id), user.email);

		await createSession({
			userId: String(user._id),
			tokenHash: hashRefreshToken(newRefreshToken),
		});

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
		console.error(_error);
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

		// Si la firma no verifica, no hay a quien atribuirle el token y no se
		// toca Redis.
		const decoded = verifyRefreshToken(cookieRefreshToken);
		if (!decoded?.id) {
			return res
				.status(403)
				.json({ success: false, message: "Refresh token inválido" });
		}

		const previousHash = hashRefreshToken(cookieRefreshToken);
		const sessionUserId = await getSessionByHash(previousHash);

		// El JWT verifica pero ese hash no esta en Redis: o nunca lo emitimos,
		// o ya fue rotado. Con Redis esto NO es el vencimiento normal, porque el
		// `EX` de la clave y el `exp` del JWT se fijaron en el mismo momento:
		// si el JWT esta vivo, la clave tambien. Huele a replay => nuke.
		if (!sessionUserId) {
			// await handlePossibleReuse(cookieRefreshToken);
			console.log("🚨 ¡Intento de reutilización de Refresh Token detectado!");
			await deleteAllSessions(decoded.id);
			console.log(
				`🔒 Todas las sesiones invalidadas para: ${decoded.username ?? decoded.id}.`,
			);
			return res
				.status(403)
				.json({ success: false, message: "Refresh token inválido" });
		}

		if (sessionUserId !== decoded.id) {
			// La sesion dice pertenecer a otro usuario que el token firmado.
			// Misma politica que el reuse: se revocan todos los tokens del
			// dueno del token presentado.
			console.log("🚨 ¡Refresh token de otro usuario detectado!");
			await deleteAllSessions(decoded.id);
			return res
				.status(403)
				.json({ success: false, message: "Refresh token manipulado" });
		}

		const accessToken = signAccessToken(decoded.id, decoded.username);

		// Rotacion: el token viejo se borra y el nuevo toma su lugar en el
		// indice, con un `jti` distinto que garantiza un hash distinto.
		const nextRefreshToken = signRefreshToken(
			decoded.id,
			decoded.username ?? "",
		);
		const nextHash = hashRefreshToken(nextRefreshToken);

		const rotated = await rotateSession({
			userId: decoded.id,
			previousHash,
			nextHash,
		});

		if (!rotated) {
			// Perdio la carrera el CAS. NO es robo y por eso NO se nukea: el
			// token matcheo en Redis hace un instante, asi que era valido y lo
			// unico que paso es que otro request del MISMO cliente lo rotó
			// primero (doble pestaña, retry, o el intervalo del front).
			// Nuke-all aca te desloguearia de todos tus dispositivos por una
			// carrera propia.
			//
			// Un token realmente robado nunca llega aca: fallaria antes, en
			// getSessionByHash, que es donde vive la deteccion de robo.
			//
			// Tampoco se vuelve a setear la cookie: la respuesta perdedora puede
			// llegar DESPUES de la ganadora, y su Set-Cookie pisaria el token
			// bueno que acaba de emitir el ganador.
			console.log(
				"Rotación perdida: otro request del mismo cliente ya rotó esto.",
			);
			return res
				.status(403)
				.json({ success: false, message: "Refresh token ya rotado" });
		}

		setRefreshCookie(res, nextRefreshToken);

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

export const logoutController = async (req: Request, res: Response) => {
	try {
		const cookieRefreshToken = req.cookies?.jwt;
		if (cookieRefreshToken) {
			// Busqueda por hash, como el deleteOne({tokenHash}) original: si el
			// token no esta en Redis no hay nada que borrar, y si esta es
			// porque lo emitimos nosotros para esa sesion.
			const tokenHash = hashRefreshToken(cookieRefreshToken);
			const userId = await getSessionByHash(tokenHash);
			if (userId) {
				await deleteSessionByHash(userId, tokenHash);
			}
		}

		clearRefreshCookie(res);

		return res
			.status(200)
			.json({ success: true, message: "Sesión cerrada correctamente" });
	} catch (_error) {
		console.error(_error);
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
