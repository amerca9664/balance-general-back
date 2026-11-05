import type { Types } from "mongoose";
import { Role } from "../models/roles.js";
import type { TokenRole } from "../types/authTypes.js";

// Sin duplicados y todos existentes en Role; null si alguno falta.
export const resolveRoles = async (roles: string[]) => {
	const unique = [...new Set(roles)];
	const found = await Role.countDocuments({ _id: { $in: unique } });
	return found === unique.length ? unique : null;
};

// Los roles del usuario como van en el token. Un _id borrado de Role se ignora.
export const loadTokenRoles = async (
	roleIds: Types.ObjectId[],
): Promise<TokenRole[]> => {
	const roles = await Role.find(
		{ _id: { $in: roleIds } },
		{ name: 1, userType: 1, permissions: 1 },
	).lean();
	return roles.map((role) => ({
		id: String(role._id),
		name: role.name,
		userType: role.userType,
		permissions: {
			read: role.permissions?.read ?? false,
			write: role.permissions?.write ?? false,
		},
	}));
};
