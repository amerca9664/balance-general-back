import "express";
import type { AuthUser } from "./authTypes.js";

declare global {
	namespace Express {
		interface Request {
			user?: AuthUser;
		}
	}
}
