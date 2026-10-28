import { PERMISSIONS, type Permission, Role } from "../models/roles.js";

/**
 * Une los permisos de todos los roles: un permiso queda si algun rol lo
 * tiene en true. Un rol que ya no existe no aporta nada.
 */
export const resolvePermissions = async (
	roleNames: string[],
): Promise<Permission[]> => {
	const roles = await Role.find(
		{ name: { $in: roleNames } },
		{ permissions: 1 },
	).lean();
	return PERMISSIONS.filter((permission) =>
		roles.some((role) => role.permissions?.[permission] === true),
	);
};
