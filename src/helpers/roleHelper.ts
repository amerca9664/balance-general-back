import type { Types } from "mongoose";
import { PERMISSIONS, type Permission, Role } from "../models/roles.js";

/**
 * Une los permisos de los roles de User.roles: queda uno si algun rol lo
 * tiene en true. Un _id que ya no existe en Role no aporta nada.
 */
export const resolvePermissions = async (
	roleIds: (Types.ObjectId | string)[],
): Promise<Permission[]> => {
	const roles = await Role.find(
		{ _id: { $in: roleIds } },
		{ permissions: 1 },
	).lean();
	return PERMISSIONS.filter((permission) =>
		roles.some((role) => role.permissions?.[permission] === true),
	);
};
