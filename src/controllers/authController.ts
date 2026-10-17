import { randomUUID } from "node:crypto";
import bcrypt from "bcrypt";
import type { Request, Response } from "express";
import {
	clearRefreshCookie,
	closePreviousSession,
	createSession,
	deleteSession,
	hashRefreshToken,
	refreshSession,
	SALT_ROUNDS,
	setRefreshCookie,
	signAccessToken,
	signRefreshToken,
	verifyRefreshToken,
} from "../helpers/authHelper.js";
import { User } from "../models/users.js";

const nowSeconds = (): number => Math.floor(Date.now() / 1000);

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
			await closePreviousSession(cookieRefreshToken);
			clearRefreshCookie(res);
		}

		const accessToken = signAccessToken(user._id, user.email);

		// Una sesion nueva = una familia nueva de refresh tokens.
		const sid = randomUUID();
		const jti = randomUUID();
		const iat = nowSeconds();
		const newRefreshToken = signRefreshToken({
			userId: String(user._id),
			username: user.email,
			sid,
			jti,
			iat,
		});

		await createSession({
			userId: String(user._id),
			sid,
			tokenHash: hashRefreshToken(newRefreshToken),
			jti,
			iat,
		});

		setRefreshCookie(res, newRefreshToken);

		return res.status(200).json({
			success: true,
			message: "ok",
			token: accessToken,
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

export const handleRefreshToken = async (req: Request, res: Response) => {
	try {
		const cookieRefreshToken = req.cookies?.jwt;
		if (!cookieRefreshToken) {
			return res
				.status(401)
				.json({ success: false, message: "Falta refresh token" });
		}

		// Si la firma no verifica, no hay a quien atribuirle el token y no se
		// toca Redis. Los tokens sin `sid` son de antes de las sesiones por
		// familia: se rechazan y el usuario vuelve a loguearse una vez.
		const decoded = verifyRefreshToken(cookieRefreshToken);
		if (!decoded?.id || !decoded.sid) {
			clearRefreshCookie(res);
			return res
				.status(403)
				.json({ success: false, message: "Refresh token inválido" });
		}

		const username = decoded.username ?? "";
		const nextJti = randomUUID();
		const nextIat = nowSeconds();
		const nextRefreshToken = signRefreshToken({
			userId: decoded.id,
			username,
			sid: decoded.sid,
			jti: nextJti,
			iat: nextIat,
		});

		const result = await refreshSession({
			userId: decoded.id,
			sid: decoded.sid,
			tokenHash: hashRefreshToken(cookieRefreshToken),
			nextHash: hashRefreshToken(nextRefreshToken),
			nextJti,
			nextIat,
		});

		if (result.status === "reuse-detected") {
			// Token viejo fuera del reuse interval: la familia esta
			// comprometida y ya se revoco esa sesion (solo esa).
			console.log(
				`🚨 Reuso de refresh token: sesión ${decoded.sid} revocada (${username || decoded.id}).`,
			);
		}

		if (result.status === "reuse-detected" || result.status === "not-found") {
			clearRefreshCookie(res);
			return res
				.status(403)
				.json({ success: false, message: "Refresh token inválido" });
		}

		// Dentro del reuse interval se reenvia el token vigente, re-firmado
		// con su jti/iat: es identico al que emitio la rotacion original.
		const refreshTokenToSend =
			result.status === "rotated"
				? nextRefreshToken
				: signRefreshToken({
						userId: decoded.id,
						username,
						sid: decoded.sid,
						jti: result.jti,
						iat: result.iat,
					});

		setRefreshCookie(res, refreshTokenToSend);
		return res.status(200).json({
			success: true,
			message: "ok",
			token: signAccessToken(decoded.id, decoded.username),
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
		const cookieRefreshToken = req.cookies?.jwt;
		if (cookieRefreshToken) {
			const decoded = verifyRefreshToken(cookieRefreshToken);
			if (decoded?.id && decoded.sid) {
				await deleteSession(decoded.id, decoded.sid);
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
