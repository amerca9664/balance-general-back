import mongoose from "mongoose";

const { Schema } = mongoose;

const userSchema = new Schema({
	username: {
		type: String,
		required: true,
	},
	email: {
		type: String,
		required: true,
		unique: true,
	},
	password: {
		type: String,
		required: true,
	},
	isAdmin: {
		type: Boolean,
		default: false,
	},
	// Los refresh tokens viven en Redis (`rt:{sha256(token)}` con TTL).
	// Un array aca no servia: no se podia auto-purgar, asi que los tokens
	// huerfanos se acumulaban para siempre y empujaban este documento contra
	// el limite de 16MB.
});
const User = mongoose.model("User", userSchema);

export { User };
