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
	// Los refresh tokens viven en RefreshTkModel con TTL.
	// Un array aca no podia auto-purgarse: el TTL de Mongo vive a nivel
	// de documento, no de campo, asi que los tokens huerfanos se acumulaban
	// para siempre y empujaban este documento contra el limite de 16MB.
});
const User = mongoose.model("User", userSchema);

export { User };
