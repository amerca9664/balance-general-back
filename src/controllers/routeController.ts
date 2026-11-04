import type { Request, Response } from "express";
import mongoose from "mongoose";
import { resolveRoles } from "../helpers/roleHelper.js";
import { registeredRouteNames } from "../middlewares/verifyToken.js";
import { Route } from "../models/routes.js";
import type {
	CreateRouteInput,
	UpdateRouteInput,
} from "../validators/routeZodSchema.js";

const serverError = (res: Response, error: unknown) => {
	console.error(error);
	return res
		.status(500)
		.json({ success: false, message: "Error interno del servidor" });
};

const notFound = (res: Response) =>
	res.status(404).json({ success: false, message: "Ruta no encontrada" });

const invalidRoles = (res: Response) =>
	res.status(400).json({ success: false, message: "Algún rol no existe" });

const duplicateName = (res: Response) =>
	res
		.status(409)
		.json({ success: false, message: "Esa ruta ya está registrada" });

const isDuplicateKey = (error: unknown) =>
	(error as { code?: number }).code === 11000;

export const listRoutesController = async (_req: Request, res: Response) => {
	try {
		const routes = await Route.find().lean();
		return res.status(200).json({ success: true, data: routes });
	} catch (error) {
		return serverError(res, error);
	}
};

// Las claves que usan los endpoints, para elegirlas en el front.
export const listRouteNamesController = (_req: Request, res: Response) =>
	res
		.status(200)
		.json({ success: true, data: [...registeredRouteNames].sort() });

export const createRouteController = async (req: Request, res: Response) => {
	try {
		const { name, module, roles = [] } = req.body as CreateRouteInput;
		const roleIds = await resolveRoles(roles);
		if (!roleIds) return invalidRoles(res);

		const route = await Route.create({ name, module, roles: roleIds });

		return res.status(201).json({
			success: true,
			message: "Ruta creada",
			data: { id: route._id },
		});
	} catch (error) {
		if (isDuplicateKey(error)) return duplicateName(res);
		return serverError(res, error);
	}
};

// Los cambios aplican en la siguiente request: requireAccess lee Route cada vez.
export const updateRouteController = async (req: Request, res: Response) => {
	try {
		const id = String(req.params.id);
		if (!mongoose.isValidObjectId(id)) return notFound(res);

		const { name, module, roles } = req.body as UpdateRouteInput;
		const roleIds = roles ? await resolveRoles(roles) : undefined;
		if (roleIds === null) return invalidRoles(res);

		const update = {
			...(name ? { name } : {}),
			...(module ? { module } : {}),
			...(roleIds ? { roles: roleIds } : {}),
		};

		const route = await Route.findByIdAndUpdate(id, update, {
			new: true,
			runValidators: true,
		}).lean();
		if (!route) return notFound(res);

		return res.status(200).json({ success: true, data: route });
	} catch (error) {
		if (isDuplicateKey(error)) return duplicateName(res);
		return serverError(res, error);
	}
};

// Borrar una ruta deja su endpoint en 403 para todos hasta crearla de nuevo.
export const deleteRouteController = async (req: Request, res: Response) => {
	try {
		const id = String(req.params.id);
		if (!mongoose.isValidObjectId(id)) return notFound(res);

		const route = await Route.findByIdAndDelete(id).lean();
		if (!route) return notFound(res);

		return res.status(200).json({ success: true, message: "Ruta eliminada" });
	} catch (error) {
		return serverError(res, error);
	}
};
