import bcrypt from "bcrypt";
import type { Request, Response } from "express";
import type { Types } from "mongoose";
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
import {
	releaseIdempotencyKey,
	storeIdempotencyKey,
} from "../helpers/idempotencyHelper.js";
import { Role } from "../models/roles.js";
import { User } from "../models/users.js";
import type { RegisterInput } from "../validators/authZodSchema.js";

export const loginController = async (req: Request, res: Response) => {
	const { email, password, idempotencyKey } = req.body;
	// La key se reserva ANTES de cualquier busqueda, asi un duplicado corta sin
	// tocar Mongo ni bcrypt. Todavia no hay userId: el dueño es el email
	// normalizado. Un duplicado siempre recibe 409.
	const owner = String(email).trim().toLowerCase();
	// true solo si esta request reservo la key: en el catch se libera para que
	// el cliente pueda reintentar con la misma key.
	let reserved = false;

	try {
		if (!(await storeIdempotencyKey(owner, idempotencyKey))) {
			return res.status(409).json({
				success: false,
				message: "Solicitud duplicada: idempotency key ya utilizada",
			});
		}
		reserved = true;

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
			token: signAccessToken(user._id, user.email, user.roles.map(String)),
			username: user.username,
		});
	} catch (_error) {
		console.error(_error);
		if (reserved) {
			await releaseIdempotencyKey(owner, idempotencyKey).catch(console.error);
		}
		return res
			.status(500)
			.json({ success: false, message: "Error interno del servidor" });
	}
};

export const registerController = async (req: Request, res: Response) => {
	try {
		const { username, email, password, roles } = req.body as RegisterInput;

		const existingUser = await User.findOne({ email });
		if (existingUser) {
			return res
				.status(409)
				.json({ success: false, message: "El email ya está registrado" });
		}

		let roleIds: (Types.ObjectId | string)[];
		if (roles) {
			// Minusculas: el mismo _id en mayusculas no debe contar dos veces.
			roleIds = [...new Set(roles.map((id) => id.toLowerCase()))];
			const found = await Role.countDocuments({ _id: { $in: roleIds } });
			if (found !== roleIds.length) {
				return res
					.status(400)
					.json({ success: false, message: "Rol inexistente" });
			}
		} else {
			// Sin roles en el body: el rol "user", que tiene que existir en Mongo.
			const defaultRole = await Role.exists({ name: "user" });
			if (!defaultRole) {
				return res.status(400).json({
					success: false,
					message: 'No existe el rol por defecto "user"',
				});
			}
			roleIds = [defaultRole._id];
		}

		const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

		const newUser = await User.create({
			username,
			email,
			password: hashedPassword,
			roles: roleIds,
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

		// Roles desde Mongo y no desde la sesion: un cambio de roles del
		// usuario o una baja aplica en el proximo refresh, sin nuevo login.
		const user = await User.findById(session.userId, { roles: 1 }).lean();
		if (!user) {
			await deleteSession(hashSessionToken(cookieSessionToken));
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
			token: signAccessToken(
				session.userId,
				session.username,
				user.roles.map(String),
			),
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
