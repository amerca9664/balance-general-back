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
	refreshTokens: {
		type: [String],
		default: [],
	},
});
const User = mongoose.model("User", userSchema);

export { User };
