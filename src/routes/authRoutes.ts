import { Router } from "express";
import {
	handleRefreshToken,
	loginController,
	logoutController,
	registerController,
} from "../controllers/authController.js";
import { validate } from "../middlewares/validate.js";
import { loginSchema, registerSchema } from "../validators/authZodSchema.js";

const authRouter: ReturnType<typeof Router> = Router();

authRouter.post("/login", validate(loginSchema), loginController);
authRouter.post("/register", validate(registerSchema), registerController);
authRouter.post("/refresh", handleRefreshToken);
authRouter.post("/logout", logoutController);

export { authRouter };
