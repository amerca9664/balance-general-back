import type { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import {
	accessTokenPayloadSchema,
	bearerHeaderSchema,
} from "../validators/authZodSchema.js";

/**
 * Valida el access token que llega en `Authorization: Bearer <token>`.
 *
 * Tres pasos, cada uno con su propia salida:
 *
 *   1. Zod sobre el header  -> 401 "Token no proporcionado" / "Token invalido"
 *      (formato `Bearer <jwt>` + estructura de JWT, sin tocar la firma)
 *   2. jsonwebtoken.verify  -> firma y expiracion
 *      vencido  -> 401 + code "TOKEN_EXPIRED" (el front refresca y reintenta)
 *      basura    -> 401 "Token invalido"
 *   3. Zod sobre el payload -> forma de lo que quedo decodificado; si no tiene
 *      `id`, no hay a quien atribuirle el token
 *
 * Si los tres pasan, `req.user` queda armado y sigue con next().
 */
export const verifyToken = (
	req: Request,
	res: Response,
	next: NextFunction,
) => {
	const rawHeader = req.headers.authorization;

	if (!rawHeader) {
		return res.status(401).json({
			success: false,
			message: "Token no proporcionado",
		});
	}

	// 1) Forma del header: extrae el token y chequea que sea un JWT bien formado.
	const headerParsed = bearerHeaderSchema.safeParse(rawHeader);
	if (!headerParsed.success) {
		return res.status(401).json({
			success: false,
			message: "Token inválido",
		});
	}

	// 2) Firma y expiracion.
	let decoded: unknown;
	try {
		decoded = jwt.verify(headerParsed.data, process.env.JWT_SECRET as string, {
			algorithms: ["HS256"],
		});
	} catch (error) {
		if (error instanceof jwt.TokenExpiredError) {
			return res.status(401).json({
				success: false,
				code: "TOKEN_EXPIRED",
				message: "Token expirado",
			});
		}

		return res.status(401).json({
			success: false,
			message: "Token inválido",
		});
	}

	// 3) Forma del payload decodificado.
	const payloadParsed = accessTokenPayloadSchema.safeParse(decoded);
	if (!payloadParsed.success) {
		return res.status(401).json({
			success: false,
			message: "Token inválido",
		});
	}

	const { id, username, sessionId } = payloadParsed.data;
	req.user = {
		id,
		username: username ?? "",
		...(sessionId ? { sessionId } : {}),
	};

	return next();
};
