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
	// _id de documentos de la coleccion Role. Sin default: el _id del rol
	// "user" no se conoce aca, lo asigna createUserController.
	roles: [{ type: Schema.Types.ObjectId, ref: "Role" }],
	// Los refresh tokens viven en Redis (`rt:{sha256(token)}` con TTL).
	// Un array aca no servia: no se podia auto-purgar, asi que los tokens
	// huerfanos se acumulaban para siempre y empujaban este documento contra
	// el limite de 16MB.
});
const User = mongoose.model("User", userSchema);

export { User };
