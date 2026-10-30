import { Router } from "express";
import {
	createUserController,
	deleteUserController,
	listUsersController,
	updateUserController,
} from "../controllers/userController.js";
import { validate } from "../middlewares/validate.js";
import { requireAccess, verifyToken } from "../middlewares/verifyToken.js";
import {
	createUserSchema,
	updateUserSchema,
} from "../validators/userZodSchema.js";

// Requiere documentos "users.read" y "users.write" en la coleccion Route.
const userRouter: ReturnType<typeof Router> = Router();

userRouter.use(verifyToken);

userRouter.get("/", requireAccess("users.read"), listUsersController);
userRouter.post(
	"/",
	requireAccess("users.write"),
	validate(createUserSchema),
	createUserController,
);
userRouter.patch(
	"/:id",
	requireAccess("users.write"),
	validate(updateUserSchema),
	updateUserController,
);
userRouter.delete("/:id", requireAccess("users.write"), deleteUserController);

export { userRouter };
