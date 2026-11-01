import type { Request, Response } from "express";
import mongoose from "mongoose";
import { Department } from "../models/departments.js";
import { Role } from "../models/roles.js";
import { Route } from "../models/routes.js";
import { User } from "../models/users.js";
import type {
	CreateRoleInput,
	UpdateRoleInput,
} from "../validators/roleZodSchema.js";

const serverError = (res: Response, error: unknown) => {
	console.error(error);
	return res
		.status(500)
		.json({ success: false, message: "Error interno del servidor" });
};

const notFound = (res: Response) =>
	res.status(404).json({ success: false, message: "Rol no encontrado" });

const duplicateName = (res: Response) =>
	res
		.status(409)
		.json({ success: false, message: "Ya existe un rol con ese nombre" });

const isDuplicateKey = (error: unknown) =>
	(error as { code?: number }).code === 11000;

const invalidDepartment = (res: Response) =>
	res
		.status(400)
		.json({ success: false, message: "El departamento no existe" });

export const listRolesController = async (_req: Request, res: Response) => {
	try {
		const roles = await Role.find().lean();
		return res.status(200).json({ success: true, data: roles });
	} catch (error) {
		return serverError(res, error);
	}
};

export const createRoleController = async (req: Request, res: Response) => {
	try {
		const { name, userType, department, permissions } =
			req.body as CreateRoleInput;
		if (!(await Department.exists({ _id: department }))) {
			return invalidDepartment(res);
		}

		const role = await Role.create({
			name,
			userType,
			department,
			permissions: {
				read: permissions?.read ?? false,
				write: permissions?.write ?? false,
			},
		});

		return res.status(201).json({
			success: true,
			message: "Rol creado",
			data: { id: role._id },
		});
	} catch (error) {
		if (isDuplicateKey(error)) return duplicateName(res);
		return serverError(res, error);
	}
};

export const updateRoleController = async (req: Request, res: Response) => {
	try {
		const id = String(req.params.id);
		if (!mongoose.isValidObjectId(id)) return notFound(res);

		// Rutas con punto para no pisar el permiso que no se envia.
		const { name, userType, department, permissions } =
			req.body as UpdateRoleInput;
		if (department && !(await Department.exists({ _id: department }))) {
			return invalidDepartment(res);
		}

		const update = {
			...(name ? { name } : {}),
			...(userType ? { userType } : {}),
			...(department ? { department } : {}),
			...(permissions?.read !== undefined
				? { "permissions.read": permissions.read }
				: {}),
			...(permissions?.write !== undefined
				? { "permissions.write": permissions.write }
				: {}),
		};

		const role = await Role.findByIdAndUpdate(id, update, {
			new: true,
			runValidators: true,
		}).lean();
		if (!role) return notFound(res);

		return res.status(200).json({ success: true, data: role });
	} catch (error) {
		if (isDuplicateKey(error)) return duplicateName(res);
		return serverError(res, error);
	}
};

// No se borra un rol asignado: el usuario quedaria sin acceso sin aviso.
export const deleteRoleController = async (req: Request, res: Response) => {
	try {
		const id = String(req.params.id);
		if (!mongoose.isValidObjectId(id)) return notFound(res);

		if (await User.exists({ roles: id })) {
			return res.status(409).json({
				success: false,
				message: "El rol está asignado a usuarios",
			});
		}

		const role = await Role.findByIdAndDelete(id).lean();
		if (!role) return notFound(res);

		await Route.updateMany({ roles: id }, { $pull: { roles: id } });

		return res.status(200).json({ success: true, message: "Rol eliminado" });
	} catch (error) {
		return serverError(res, error);
	}
};
