import { createHash } from "node:crypto";
import { getRedisClient } from "../dbs/redis.js";
import { readPositiveIntEnv } from "./authHelper.js";

// ---------------------------------------------------------------------------
// Idempotency store (Redis)
//
//   idem:{sha256(owner)}:{sha256(idempotencyKey)} STRING "1"
//                                       TTL = IDEMPOTENCY_TTL_MINUTES (10)
//
// Solo se guarda que la key ya se uso: ni metadatos ni respuesta. Un duplicado
// dentro del TTL recibe 409. 10 minutos cubren doble submit y reintentos del
// front; mas tiempo solo ocupa memoria.
//
// La key va namespaceada por usuario (`owner`: el userId, o el email cuando
// todavia no se busco al usuario, como en login): la misma idempotencyKey de
// dos usuarios distintos son dos registros distintos. Ambas partes se
// hashean: la key la manda el cliente (no puede inflar el nombre ni meter
// caracteres raros) y el email es dato personal que no tiene que quedar
// legible en el nombre de la key.
// ---------------------------------------------------------------------------

const IDEMPOTENCY_TTL_SECONDS =
	readPositiveIntEnv("IDEMPOTENCY_TTL_MINUTES", 10) * 60;

const sha256 = (value: string): string =>
	createHash("sha256").update(value).digest("hex");

const idempotencyKeyName = (owner: string, idempotencyKey: string): string =>
	`idem:${sha256(owner)}:${sha256(idempotencyKey)}`;

/**
 * Reserva la idempotencyKey del usuario. Atomico (`SET NX`): si dos requests
 * con la misma key llegan juntas, solo una la reserva.
 *
 * `true` = key nueva, procesar la request. `false` = duplicado.
 */
export const storeIdempotencyKey = async (
	owner: string,
	idempotencyKey: string,
): Promise<boolean> => {
	const result = await getRedisClient().set(
		idempotencyKeyName(owner, idempotencyKey),
		"1",
		"EX",
		IDEMPOTENCY_TTL_SECONDS,
		"NX",
	);
	return result === "OK";
};

/**
 * Libera la key si la request fallo: el cliente puede reintentar con la misma
 * key en vez de quedar bloqueado hasta que venza el TTL.
 */
export const releaseIdempotencyKey = async (
	owner: string,
	idempotencyKey: string,
): Promise<void> => {
	await getRedisClient().del(idempotencyKeyName(owner, idempotencyKey));
};
