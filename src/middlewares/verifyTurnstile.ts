import type { NextFunction, Request, Response } from "express";
import { getRequestMeta } from "../helpers/authHelper.js";
import { verifyTurnstileToken } from "../helpers/turnstileHelper.js";

/**
 * Middleware que exige un Turnstile valido antes de dejar pasar el request.
 *
 * Se engancha despues de `express.json()` (si no, `req.body` no existe) y
 * antes del handler real. El `action` debe coincidir con el `data-action` que
 * el front le puso al widget.
 */
export const verifyTurnstile =
	(action: string) =>
	async (req: Request, res: Response, next: NextFunction): Promise<void> => {
		// En desarrollo el captcha no se monta en el front: se omite la verificacion.
		if (process.env.NODE_ENV !== "production") {
			next();
			return;
		}

		const token = (req.body as Record<string, unknown> | undefined)?.[
			"cf-turnstile-response"
		];

		const isValid = await verifyTurnstileToken({
			token,
			remoteip: getRequestMeta(req).ip,
			expectedAction: action,
		});

		if (!isValid) {
			res.status(403).json({
				success: false,
				message: "Verificación de bot fallida",
			});
			return;
		}

		next();
	};
