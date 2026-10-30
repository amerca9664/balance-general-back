import mongoose from "mongoose";

const { Schema } = mongoose;

// Quien puede entrar a cada endpoint. `name` es la clave que el endpoint
// pasa a requireAccess (ej. "users.write"), no el path.
const routeSchema = new Schema({
	name: {
		type: String,
		required: true,
		unique: true,
	},
	roles: [{ type: Schema.Types.ObjectId, ref: "Role" }],
});
const Route = mongoose.model("Route", routeSchema);

export { Route };
