import { z } from "zod";

// Crear y editar piden lo mismo: el nombre es el unico campo.
export const departmentSchema = z.object({
	name: z.string().trim().min(2, "El nombre debe tener al menos 2 caracteres"),
});

export type DepartmentInput = z.infer<typeof departmentSchema>;
