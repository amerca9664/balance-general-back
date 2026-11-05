import { Router } from "express";
import {
	createRouteController,
	deleteRouteController,
	listRouteNamesController,
	listRoutesController,
	updateRouteController,
} from "../controllers/routeController.js";
import { validate } from "../middlewares/validate.js";
import { requireAccess, verifyToken } from "../middlewares/verifyToken.js";
import {
	createRouteSchema,
	updateRouteSchema,
} from "../validators/routeZodSchema.js";

// Requiere el documento "routes" en la coleccion Route; read/write salen del Role.
const routeRouter: ReturnType<typeof Router> = Router();

routeRouter.use(verifyToken);

routeRouter.get("/", requireAccess("routes", "read"), listRoutesController);
routeRouter.get(
	"/names",
	requireAccess("routes", "read"),
	listRouteNamesController,
);
routeRouter.post(
	"/",
	requireAccess("routes", "write"),
	validate(createRouteSchema),
	createRouteController,
);
routeRouter.patch(
	"/:id",
	requireAccess("routes", "write"),
	validate(updateRouteSchema),
	updateRouteController,
);
routeRouter.delete(
	"/:id",
	requireAccess("routes", "write"),
	deleteRouteController,
);

export { routeRouter };
