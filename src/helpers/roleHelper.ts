import { Role } from "../models/roles.js";

// Sin duplicados y todos existentes en Role; null si alguno falta.
export const resolveRoles = async (roles: string[]) => {
	const unique = [...new Set(roles)];
	const found = await Role.countDocuments({ _id: { $in: unique } });
	return found === unique.length ? unique : null;
};
