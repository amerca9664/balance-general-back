import bcrypt from "bcrypt";
import type { Request, Response } from "express";
import {
	clearSessionCookie,
	createSession,
	deleteSession,
	generateSessionToken,
	getRequestMeta,
	hashSessionToken,
	SALT_ROUNDS,
	setSessionCookie,
	signAccessToken,
	touchSession,
} from "../helpers/authHelper.js";
import { User } from "../models/users.js";

export const loginController = async (req: Request, res: Response) => {
	try {
		const { email, password } = req.body;
		const cookieSessionToken = req.cookies?.jwt;

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

		if (cookieSessionToken) {
			// Login encima de una sesion previa del mismo navegador: se cierra
			// para que no quede colgada. El resto de las sesiones queda intacto.
			await deleteSession(hashSessionToken(cookieSessionToken));
		}

		const sessionToken = generateSessionToken();
		await createSession({
			userId: String(user._id),
			username: user.email,
			tokenHash: hashSessionToken(sessionToken),
			meta: getRequestMeta(req),
		});

		setSessionCookie(res, sessionToken);

		return res.status(200).json({
			success: true,
			message: "ok",
			token: signAccessToken(user._id, user.email),
			username: user.username,
		});
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

/**
 * Emite un access token nuevo a partir de la cookie de sesion.
 *
 * No rota el token de sesion: es idempotente, asi que refresh concurrentes o
 * repetidos (F5, varias pestañas, reintentos tras un 429) nunca se pisan.
 * Solo extiende el vencimiento por inactividad, en Redis y en la cookie.
 */
export const handleRefreshToken = async (req: Request, res: Response) => {
	try {
		const cookieSessionToken = req.cookies?.jwt;
		if (!cookieSessionToken) {
			return res
				.status(401)
				.json({ success: false, message: "Falta refresh token" });
		}

		const session = await touchSession(
			hashSessionToken(cookieSessionToken),
			getRequestMeta(req),
		);
		if (!session) {
			clearSessionCookie(res);
			return res
				.status(403)
				.json({ success: false, message: "Refresh token inválido" });
		}

		// Mismo token, vencimiento renovado: la cookie acompaña al TTL de Redis.
		setSessionCookie(res, cookieSessionToken);
		return res.status(200).json({
			success: true,
			message: "ok",
			token: signAccessToken(session.userId, session.username),
		});
	} catch (_error) {
		console.error(_error);
		return res
			.status(500)
			.json({ success: false, message: "Error interno del servidor" });
	}
};

export const logoutController = async (req: Request, res: Response) => {
	try {
		const cookieSessionToken = req.cookies?.jwt;
		if (cookieSessionToken) {
			await deleteSession(hashSessionToken(cookieSessionToken));
		}

		clearSessionCookie(res);

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
