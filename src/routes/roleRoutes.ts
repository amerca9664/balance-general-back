import { Router } from "express";
import {
	createRoleController,
	deleteRoleController,
	listRolesController,
	updateRoleController,
} from "../controllers/roleController.js";
import { validate } from "../middlewares/validate.js";
import { requireAccess, verifyToken } from "../middlewares/verifyToken.js";
import {
	createRoleSchema,
	updateRoleSchema,
} from "../validators/roleZodSchema.js";

// Requiere el documento "roles" en la coleccion Route; read/write salen del Role.
const roleRouter: ReturnType<typeof Router> = Router();

roleRouter.use(verifyToken);

roleRouter.get("/", requireAccess("roles", "read"), listRolesController);
roleRouter.post(
	"/",
	requireAccess("roles", "write"),
	validate(createRoleSchema),
	createRoleController,
);
roleRouter.patch(
	"/:id",
	requireAccess("roles", "write"),
	validate(updateRoleSchema),
	updateRoleController,
);
roleRouter.delete(
	"/:id",
	requireAccess("roles", "write"),
	deleteRoleController,
);

export { roleRouter };
