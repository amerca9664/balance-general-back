import mongoose from "mongoose";
import { z } from "zod";
import { registeredRouteNames } from "../middlewares/verifyToken.js";

export const createRouteSchema = z.object({
	// Solo claves que algun endpoint pasa a requireAccess.
	name: z
		.string()
		.refine((name) => registeredRouteNames.has(name), "Ruta no válida"),
	// Los modulos los define el front (Sidebar); aca solo se exige uno.
	module: z.string().trim().min(1, "Módulo no válido"),
	// _id de documentos Role; que existan lo revisa el controller.
	roles: z
		.array(z.string().refine(mongoose.isValidObjectId, "Rol no válido"))
		.optional(),
});

// Mismas reglas que al crear; en una edicion cada campo es opcional.
export const updateRouteSchema = createRouteSchema.partial();

export type CreateRouteInput = z.infer<typeof createRouteSchema>;
export type UpdateRouteInput = z.infer<typeof updateRouteSchema>;
