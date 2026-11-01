import bcrypt from "bcrypt";
import type { Request, Response } from "express";
import mongoose from "mongoose";
import { SALT_ROUNDS } from "../helpers/authHelper.js";
import { Role } from "../models/roles.js";
import { User } from "../models/users.js";
import type {
	CreateUserInput,
	UpdateUserInput,
} from "../validators/userZodSchema.js";

const serverError = (res: Response, error: unknown) => {
	console.error(error);
	return res
		.status(500)
		.json({ success: false, message: "Error interno del servidor" });
};

const notFound = (res: Response) =>
	res.status(404).json({ success: false, message: "Usuario no encontrado" });

const invalidRoles = (res: Response) =>
	res.status(400).json({ success: false, message: "Algún rol no existe" });

// Sin duplicados y todos existentes en Role; null si alguno falta.
const resolveRoles = async (roles: string[]) => {
	const unique = [...new Set(roles)];
	const found = await Role.countDocuments({ _id: { $in: unique } });
	return found === unique.length ? unique : null;
};

const USER_PROJECTION = { username: 1, email: 1, roles: 1 };

// shortcut: sin paginacion, devuelve todos; paginar cuando sean miles.
export const listUsersController = async (_req: Request, res: Response) => {
	try {
		const users = await User.find({}, USER_PROJECTION).lean();
		return res.status(200).json({ success: true, data: users });
	} catch (error) {
		return serverError(res, error);
	}
};

export const createUserController = async (req: Request, res: Response) => {
	try {
		const {
			username,
			email,
			password,
			roles = [],
		} = req.body as CreateUserInput;

		const roleIds = await resolveRoles(roles);
		if (!roleIds) return invalidRoles(res);

		const existingUser = await User.findOne({ email });
		if (existingUser) {
			return res
				.status(409)
				.json({ success: false, message: "El email ya está registrado" });
		}

		const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

		const newUser = await User.create({
			username,
			email,
			password: hashedPassword,
			roles: roleIds,
		});

		return res.status(201).json({
			success: true,
			message: "Usuario creado",
			data: { id: newUser._id },
		});
	} catch (_error) {
		console.error(_error);
		return res
			.status(500)
			.json({ success: false, message: "Error interno del servidor" });
	}
};

export const updateUserController = async (req: Request, res: Response) => {
	try {
		const id = String(req.params.id);
		if (!mongoose.isValidObjectId(id)) return notFound(res);

		// Solo estos campos: validate no recorta el body, asi que nada mas se cuela.
		const { username, email, password, roles } = req.body as UpdateUserInput;
		const roleIds = roles ? await resolveRoles(roles) : undefined;
		if (roleIds === null) return invalidRoles(res);

		// Los roles nuevos entran al token en el proximo refresh.
		const update = {
			...(roleIds ? { roles: roleIds } : {}),
			...(username ? { username } : {}),
			...(email ? { email } : {}),
			...(password
				? { password: await bcrypt.hash(password, SALT_ROUNDS) }
				: {}),
		};

		const user = await User.findByIdAndUpdate(id, update, {
			new: true,
			projection: USER_PROJECTION,
		}).lean();
		if (!user) return notFound(res);

		return res.status(200).json({ success: true, data: user });
	} catch (error) {
		if ((error as { code?: number }).code === 11000) {
			return res
				.status(409)
				.json({ success: false, message: "El email ya está registrado" });
		}
		return serverError(res, error);
	}
};

// La sesion del usuario borrado muere en su proximo refresh (no encuentra el User).
export const deleteUserController = async (req: Request, res: Response) => {
	try {
		const id = String(req.params.id);
		if (id === req.user?.id) {
			return res
				.status(400)
				.json({ success: false, message: "No puedes eliminar tu usuario" });
		}
		if (!mongoose.isValidObjectId(id)) return notFound(res);

		const user = await User.findByIdAndDelete(id).lean();
		if (!user) return notFound(res);

		return res
			.status(200)
			.json({ success: true, message: "Usuario eliminado" });
	} catch (error) {
		return serverError(res, error);
	}
};
