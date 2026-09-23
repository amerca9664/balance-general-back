import bcrypt from "bcrypt";
import type { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { User } from "../models/users.js";

interface RefreshTokenPayload extends jwt.JwtPayload {
	id?: string;
	username?: string;
}

const SALT_ROUNDS = 10;
// 1. Detecta si el entorno actual es producción
const IS_PRODUCTION = process.env.NODE_ENV === "production";
export const loginController = async (req: Request, res: Response) => {
	try {
		const cookies = req.cookies;
		const refreshToken = cookies?.jwt;
		console.log(refreshToken);
		const { email, password } = req.body;

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

		const accessToken = jwt.sign(
			{ id: user._id, username: user.email },
			process.env.JWT_SECRET as string,
			{
				expiresIn: "1h",
			},
		);

		const newRefreshToken = jwt.sign(
			{ id: user._id, username: user.email },
			process.env.JWT_SECRET as string,
			{ expiresIn: "6d" },
		);

		// Changed to let keyword
		let newRefreshTokenArray = !cookies?.jwt
			? user.refreshTokens
			: user.refreshTokens.filter((rt) => rt !== cookies.jwt);

		if (cookies?.jwt) {
			/* 
            Scenario added here: 
                1) User logs in but never uses RT and does not logout 
                2) RT is stolen
                3) If 1 & 2, reuse detection is needed to clear all RTs when user logs in
            */
			const refreshToken = cookies.jwt;
			const foundToken = await User.findOne({
				refreshTokens: refreshToken,
			}).exec();

			// Detected refresh token reuse!
			if (!foundToken) {
				console.log("attempted refresh token reuse at login!");
				// clear out ALL previous refresh tokens
				newRefreshTokenArray = [];
			}

			res.clearCookie("jwt", {
				httpOnly: true,
				sameSite: IS_PRODUCTION ? "none" : "lax",
				secure: IS_PRODUCTION,
			});
		}
		user.refreshTokens = [...newRefreshTokenArray, newRefreshToken];
		await user.save();

		// Creates Secure Cookie with refresh token
		res.cookie("jwt", newRefreshToken, {
			httpOnly: true,
			secure: IS_PRODUCTION,
			sameSite: IS_PRODUCTION ? "none" : "lax",
			maxAge: 24 * 60 * 60 * 1000,
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
	const cookies = req.cookies;
	if (!cookies?.jwt) return res.sendStatus(401);
	const refreshToken = cookies.jwt;
	console.log(refreshToken);
	res.clearCookie("jwt", {
		httpOnly: true,
		sameSite: IS_PRODUCTION ? "none" : "lax",
		secure: IS_PRODUCTION,
	});

	const foundUser = await User.findOne({ refreshTokens: refreshToken }).exec();

	// Detected refresh token reuse!
	if (!foundUser) {
		try {
			// Verificamos el token de forma síncrona/secuencial
			// Forzamos el tipo al payload que nosotros mismos creamos
			const decoded = jwt.verify(
				refreshToken,
				process.env.JWT_SECRET as string, // Usa el mismo secret con el que firmaste el RT en el login
			) as RefreshTokenPayload;

			console.log("🚨 ¡Intento de reutilización de Refresh Token detectado!");

			if (typeof decoded === "string" || !decoded.id) {
				console.log("Token viejo e inválido (expirado o manipulado).");
				return res.sendStatus(403);
			}

			// Buscamos al usuario afectado usando el valor decodificado
			// OJO: en el login firmas con { id: user._id, ... }, no con _id
			const hackedUser = await User.findOne({
				_id: decoded.id,
			}).exec();

			if (hackedUser) {
				hackedUser.refreshTokens = []; // Castigo: Vaciamos todas sus sesiones activas
				await hackedUser.save();
				console.log(
					`🔒 Cuenta protegida para el usuario: ${decoded.username}. Sesiones invalidadas.`,
				);
			}
		} catch (err) {
			// Si el token además de ser viejo está mal firmado o expiró,
			// jwt.verify lanzará un error y caerá aquí.
			console.log("Token viejo e inválido (expirado o manipulado).");
		}

		// Enviamos el 403 AL FINAL, asegurándonos de que la DB ya se actualizó si el token era válido
		return res.sendStatus(403); // Forbidden
	}

	const newRefreshTokenArray = foundUser.refreshTokens.filter(
		(rt) => rt !== refreshToken,
	);

	try {
		const decoded = jwt.verify(
			refreshToken,
			process.env.JWT_SECRET as string,
		) as RefreshTokenPayload;

		if (foundUser.email !== decoded.username) {
			console.log("Token viejo e inválido (expirado o manipulado).");
			return res.sendStatus(403);
		}

		const accessToken = jwt.sign(
			{ id: foundUser._id, username: foundUser.email },
			process.env.JWT_SECRET as string,
			{
				expiresIn: "1h",
			},
		);

		const newRefreshToken = jwt.sign(
			{ id: foundUser._id, username: foundUser.email },
			process.env.JWT_SECRET as string,
			{ expiresIn: "6d" },
		);

		foundUser.refreshTokens = [...newRefreshTokenArray, newRefreshToken];
		await foundUser.save();

		// Creates Secure Cookie with refresh token
		res.cookie("jwt", newRefreshToken, {
			httpOnly: true,
			secure: IS_PRODUCTION,
			sameSite: IS_PRODUCTION ? "none" : "lax",
			maxAge: 24 * 60 * 60 * 1000,
		});

		return res
			.status(200)
			.json({ success: true, message: "ok", token: accessToken });
	} catch (err) {
		console.log("Token viejo ");
		foundUser.refreshTokens = [...newRefreshTokenArray];
		const result = await foundUser.save();
		console.log(result);
		return res.sendStatus(403);
	}
};

export const logoutController = async (req: Request, res: Response) => {
	try {
		// Invalidate the token on the client side by instructing the client to remove it
		return res
			.status(200)
			.json({ success: true, message: "Sesión cerrada correctamente" });
	} catch (_error) {
		return res
			.status(500)
			.json({ success: false, message: "Error interno del servidor" });
	}
};
