import { Router } from "express";
import {
	handleRefreshToken,
	loginController,
	logoutController,
	meController,
	registerController,
} from "../controllers/authController.js";
import {
	loginIpRateLimit,
	loginUserIpRateLimit,
} from "../middlewares/loginRateLimit.js";
import { validate } from "../middlewares/validate.js";
import { requirePermission, verifyToken } from "../middlewares/verifyToken.js";
import { verifyTurnstile } from "../middlewares/verifyTurnstile.js";
import { loginSchema, registerSchema } from "../validators/authZodSchema.js";

const authRouter: ReturnType<typeof Router> = Router();

authRouter.post(
	"/login",
	verifyTurnstile("login"),
	validate(loginSchema),
	loginIpRateLimit,
	loginUserIpRateLimit,
	loginController,
);
authRouter.post(
	"/register",
	verifyToken,
	requirePermission("users:create"),
	validate(registerSchema),
	registerController,
);
authRouter.post("/refresh", handleRefreshToken);
authRouter.post("/logout", logoutController);

// Rutas protegidas: van con Authorization: Bearer <access token>
authRouter.get("/me", verifyToken, meController);

export { authRouter };
