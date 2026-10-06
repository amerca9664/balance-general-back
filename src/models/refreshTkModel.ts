import mongoose from "mongoose";

const { Schema } = mongoose;

const refreshTkModelSchema = new Schema(
	{
		idUser: {
			type: Schema.Types.ObjectId,
			ref: "User",
			required: true,
			index: true,
		},
		// Nombre explicito: esto es un SHA-256, nunca el token crudo.
		tokenHash: {
			type: String,
			required: true,
			unique: true,
		},
		createdAt: {
			type: Date,
			default: Date.now,
		},
		// TTL de Mongo: el documento se borra solo, sin job de limpieza.
		// Resuelve el caso "el cliente borro sus datos y nunca mas nos aviso".
		expiresAt: {
			type: Date,
			required: true,
		},
	},
	{ versionKey: false },
);

refreshTkModelSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const RefreshTkModel = mongoose.model("RefreshTkModel", refreshTkModelSchema);

export { RefreshTkModel };
