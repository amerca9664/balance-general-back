import mongoose from "mongoose";
import { z } from "zod";

export const createUserSchema = z.object({
	username: z
		.string()
		.min(3, "El nombre de usuario debe tener al menos 3 caracteres"),
	email: z.string().email("El email no es válido"),
	password: z.string().min(6, "La contraseña debe tener al menos 6 caracteres"),
	// _id de documentos Role; que existan lo revisa el controller.
	roles: z
		.array(z.string().refine(mongoose.isValidObjectId, "Rol no válido"))
		.optional(),
});

// Mismas reglas que al crear; en una edicion cada campo es opcional.
export const updateUserSchema = createUserSchema.partial();

export type CreateUserInput = z.infer<typeof createUserSchema>;
export type UpdateUserInput = z.infer<typeof updateUserSchema>;
