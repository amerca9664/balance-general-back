import mongoose from "mongoose";

const { Schema } = mongoose;

// Quien puede entrar a cada endpoint. `name` es la clave que el endpoint
// pasa a requireAccess (ej. "users.write"), no el path. Las claves validas
// salen de registeredRouteNames (middlewares/verifyToken.ts).
const routeSchema = new Schema({
	name: {
		type: String,
		required: true,
		unique: true,
	},
	// Modulo del front al que pertenece la ruta; la lista vive en el front.
	module: {
		type: String,
		required: true,
	},
	roles: [{ type: Schema.Types.ObjectId, ref: "Role" }],
});
const Route = mongoose.model("Route", routeSchema);

export { Route };
