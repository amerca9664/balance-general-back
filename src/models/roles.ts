import mongoose from "mongoose";

const { Schema } = mongoose;

// Lo que el codigo sabe proteger. Los roles (y que permisos tiene cada uno)
// viven en Mongo y se editan sin deployar; un permiso nuevo si requiere codigo.
export const PERMISSIONS = ["users:create"] as const;
export type Permission = (typeof PERMISSIONS)[number];

const roleSchema = new Schema({
	name: {
		type: String,
		required: true,
		unique: true,
	},
	permissions: {
		type: [{ type: String, enum: PERMISSIONS }],
		default: [],
	},
});
const Role = mongoose.model("Role", roleSchema);

export { Role };
