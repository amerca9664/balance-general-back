import { type Permission, Role } from "../models/roles.js";

/** Une los permisos de todos los roles. Un rol que ya no existe no aporta nada. */
export const resolvePermissions = async (
	roleNames: string[],
): Promise<Permission[]> => {
	const roles = await Role.find(
		{ name: { $in: roleNames } },
		{ permissions: 1 },
	).lean();
	return [
		...new Set(roles.flatMap((role) => role.permissions as Permission[])),
	];
};
