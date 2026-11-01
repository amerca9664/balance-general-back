import type { Request, Response } from "express";
import mongoose from "mongoose";
import { Department } from "../models/departments.js";
import { Role } from "../models/roles.js";
import type { DepartmentInput } from "../validators/departmentZodSchema.js";

const serverError = (res: Response, error: unknown) => {
	console.error(error);
	return res
		.status(500)
		.json({ success: false, message: "Error interno del servidor" });
};

const notFound = (res: Response) =>
	res
		.status(404)
		.json({ success: false, message: "Departamento no encontrado" });

const duplicateName = (res: Response) =>
	res.status(409).json({
		success: false,
		message: "Ya existe un departamento con ese nombre",
	});

const isDuplicateKey = (error: unknown) =>
	(error as { code?: number }).code === 11000;

export const listDepartmentsController = async (
	_req: Request,
	res: Response,
) => {
	try {
		const departments = await Department.find().lean();
		return res.status(200).json({ success: true, data: departments });
	} catch (error) {
		return serverError(res, error);
	}
};

export const createDepartmentController = async (
	req: Request,
	res: Response,
) => {
	try {
		const { name } = req.body as DepartmentInput;
		const department = await Department.create({ name });

		return res.status(201).json({
			success: true,
			message: "Departamento creado",
			data: { id: department._id },
		});
	} catch (error) {
		if (isDuplicateKey(error)) return duplicateName(res);
		return serverError(res, error);
	}
};

export const updateDepartmentController = async (
	req: Request,
	res: Response,
) => {
	try {
		const id = String(req.params.id);
		if (!mongoose.isValidObjectId(id)) return notFound(res);

		const { name } = req.body as DepartmentInput;
		const department = await Department.findByIdAndUpdate(
			id,
			{ name },
			{ new: true },
		).lean();
		if (!department) return notFound(res);

		return res.status(200).json({ success: true, data: department });
	} catch (error) {
		if (isDuplicateKey(error)) return duplicateName(res);
		return serverError(res, error);
	}
};

// No se borra un departamento en uso: el rol quedaria apuntando a nada.
export const deleteDepartmentController = async (
	req: Request,
	res: Response,
) => {
	try {
		const id = String(req.params.id);
		if (!mongoose.isValidObjectId(id)) return notFound(res);

		if (await Role.exists({ department: id })) {
			return res.status(409).json({
				success: false,
				message: "El departamento está asignado a roles",
			});
		}

		const department = await Department.findByIdAndDelete(id).lean();
		if (!department) return notFound(res);

		return res
			.status(200)
			.json({ success: true, message: "Departamento eliminado" });
	} catch (error) {
		return serverError(res, error);
	}
};
