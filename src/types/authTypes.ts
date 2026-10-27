import type { Permission } from "../models/roles.js";

export type AuthUser = {
	id: string;
	username: string;
	roles: string[];
	permissions: Permission[];
};
