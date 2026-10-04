import { createHash } from "node:crypto";
import mongoose from "mongoose";

const { Schema } = mongoose;

const REFRESH_TOKEN_TTL_DAYS = 6;
const REFRESH_TOKEN_TTL_MS = REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000;
const MAX_SESSIONS_PER_USER = 5;

/**
 * Hash DETERMINISTA a proposito.
 *
 * bcrypt no sirve aca: es salado, asi que no existe forma de armar
 * `WHERE tokenHash = ?` con el token crudo que llega en la cookie.
 * Solo podes hacer compare() contra un candidato que ya trajiste.
 *
 * SHA-256 si es determinista, asi que la busqueda es un lookup indexado.
 * No lleva sal a proposito: el token tiene ~250 bits de entropia,
 * no existe ataque de diccionario. La sal solo sirve para secretos
 * de baja entropia (passwords) y rompe justamente la propiedad
 * que nos permite buscar.
 */
export const hashRefreshToken = (rawToken: string): string =>
	createHash("sha256").update(rawToken).digest("hex");

export const getRefreshExpiry = (): Date =>
	new Date(Date.now() + REFRESH_TOKEN_TTL_MS);

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

export {
	MAX_SESSIONS_PER_USER,
	REFRESH_TOKEN_TTL_DAYS,
	REFRESH_TOKEN_TTL_MS,
	RefreshTkModel,
};
