import mongoose from "mongoose";

const { Schema } = mongoose;

export const USER_TYPES = ["user", "superuser", "supervisor", "admin"] as const;
export type UserType = (typeof USER_TYPES)[number];

const roleSchema = new Schema({
	name: {
		type: String,
		required: true,
		unique: true,
	},
	permissions: {
		read: { type: Boolean, default: false },
		write: { type: Boolean, default: false },
	},
	userType: {
		type: String,
		enum: USER_TYPES,
		required: true,
	},
});
const Role = mongoose.model("Role", roleSchema);

export { Role };
