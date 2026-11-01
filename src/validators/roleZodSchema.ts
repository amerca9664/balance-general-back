import { z } from "zod";
import { USER_TYPES } from "../models/roles.js";

export const createRoleSchema = z.object({
	name: z.string().trim().min(2, "El nombre debe tener al menos 2 caracteres"),
	userType: z.enum(USER_TYPES, "Tipo de usuario no válido"),
	permissions: z
		.object({
			read: z.boolean().optional(),
			write: z.boolean().optional(),
		})
		.optional(),
});

// Mismas reglas que al crear; en una edicion cada campo es opcional.
export const updateRoleSchema = createRoleSchema.partial();

export type CreateRoleInput = z.infer<typeof createRoleSchema>;
export type UpdateRoleInput = z.infer<typeof updateRoleSchema>;
