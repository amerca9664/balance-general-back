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

export const authTokenSchema = z.object({
	authorization: z.jwt().refine((token) => token.startsWith("Bearer "), {
		message: "Token inválido",
	}),
});

export type LoginInput = z.infer<typeof loginSchema>;
export type RegisterInput = z.infer<typeof registerSchema>;
export type AuthTokenInput = z.infer<typeof authTokenSchema>;
