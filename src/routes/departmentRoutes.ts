import { Router } from "express";
import {
	createDepartmentController,
	deleteDepartmentController,
	listDepartmentsController,
	updateDepartmentController,
} from "../controllers/departmentController.js";
import { validate } from "../middlewares/validate.js";
import { requireAccess, verifyToken } from "../middlewares/verifyToken.js";
import { departmentSchema } from "../validators/departmentZodSchema.js";

// Requiere documentos "departments.read" y "departments.write" en la coleccion Route.
const departmentRouter: ReturnType<typeof Router> = Router();

departmentRouter.use(verifyToken);

departmentRouter.get(
	"/",
	requireAccess("departments.read"),
	listDepartmentsController,
);
departmentRouter.post(
	"/",
	requireAccess("departments.write"),
	validate(departmentSchema),
	createDepartmentController,
);
departmentRouter.patch(
	"/:id",
	requireAccess("departments.write"),
	validate(departmentSchema),
	updateDepartmentController,
);
departmentRouter.delete(
	"/:id",
	requireAccess("departments.write"),
	deleteDepartmentController,
);

export { departmentRouter };
