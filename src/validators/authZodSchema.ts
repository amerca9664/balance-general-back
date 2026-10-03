import { z } from "zod";

export const loginSchema = z.object({
	email: z.string().email("El email no es válido"),
	password: z.string().min(6, "La contraseña debe tener al menos 6 caracteres"),
});

export const registerSchema = z.object({
	username: z
		.string()
		.min(3, "El nombre de usuario debe tener al menos 3 caracteres"),
	email: z.string().email("El email no es válido"),
	password: z.string().min(6, "La contraseña debe tener al menos 6 caracteres"),
	isAdmin: z.boolean().optional(),
});

/**
 * Valida el header `Authorization` completo y deja solo el token.
 *
 * El transform va ANTES del pipe a z.jwt(): si el regex no matchea,
 * `ctx.addIssue` corta la cadena y nunca llega a validar el JWT.
 * Era el problema del schema anterior (`z.jwt()` sobre "Bearer xxx"
 * siempre fallaba, asi que no podia pasar nunca).
 */
export const bearerHeaderSchema = z
	.string()
	.transform((value, ctx) => {
		const match = /^Bearer\s+(\S+)$/i.exec(value.trim());
		if (!match?.[1]) {
			ctx.addIssue({ code: "custom", message: "Token inválido" });
			return z.NEVER;
		}
		return match[1];
	})
	.pipe(z.jwt("Token inválido"));

/**
 * Forma del payload de un access token firmado por este back
 * (`{ id, username }` en login, `{ id, username }` en refresh).
 * Zod descarta las claves extra (`iat`, `exp`, `alg`) al parsear.
 */
export const accessTokenPayloadSchema = z.object({
	id: z.string().min(1, "Token inválido"),
	username: z.string().optional(),
	sessionId: z.string().optional(),
});

export type LoginInput = z.infer<typeof loginSchema>;
export type RegisterInput = z.infer<typeof registerSchema>;
export type BearerHeaderInput = z.infer<typeof bearerHeaderSchema>;
export type AccessTokenPayloadInput = z.infer<typeof accessTokenPayloadSchema>;
