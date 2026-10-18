import { connectRedis } from "./src/dbs/redis.js";
import * as h from "./src/helpers/authHelper.js";

const r = connectRedis();
let failures = 0;

const check = (name: string, got: unknown, want: unknown) => {
	const ok =
		Object.is(got, want) || JSON.stringify(got) === JSON.stringify(want);
	if (!ok) failures++;
	console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
	if (!ok)
		console.log(
			`        got  = ${String(got)}\n        want = ${String(want)}`,
		);
};

const tag = Date.now();
const uid = `itest-${tag}`;
const uid2 = `itest2-${tag}`;
const hashes: string[] = [];

/** Crea una sesion de prueba y devuelve el hash de su token. */
const newSession = async (userId: string) => {
	const tokenHash = h.hashSessionToken(h.generateSessionToken());
	hashes.push(tokenHash);
	await h.createSession({ userId, username: "itest", tokenHash });
	return tokenHash;
};

try {
	await r.ping();

	console.log("--- create / touch ---");
	const s1 = await newSession(uid);
	check("touch devuelve la sesion", await h.touchSession(s1), {
		userId: uid,
		username: "itest",
	});
	check(
		"token desconocido -> null",
		await h.touchSession(h.hashSessionToken("nunca")),
		null,
	);
	check(
		"zset del usuario tiene el hash",
		await r.zrange(`user:${uid}:sessions`, 0, -1),
		[s1],
	);

	console.log("\n--- idempotente: muchos touch concurrentes ---");
	const burst = await Promise.all(
		Array.from({ length: 10 }, () => h.touchSession(s1)),
	);
	check(
		"los 10 devuelven la sesion",
		burst.every((s) => s?.userId === uid),
		true,
	);
	check("la sesion sigue existiendo", await r.exists(`session:${s1}`), 1);

	console.log("\n--- sliding expiration ---");
	await r.expire(`session:${s1}`, 10);
	await h.touchSession(s1);
	check(
		"touch vuelve a extender el TTL",
		(await r.ttl(`session:${s1}`)) > 10,
		true,
	);

	console.log("\n--- vida maxima absoluta ---");
	const s2 = await newSession(uid);
	await r.hset(`session:${s2}`, "createdAt", "0");
	check("sesion demasiado vieja -> null", await h.touchSession(s2), null);
	check("y se borra", await r.exists(`session:${s2}`), 0);
	check("y sale del zset", await r.zrange(`user:${uid}:sessions`, 0, -1), [s1]);

	console.log("\n--- cap de sesiones ---");
	const cap: string[] = [];
	for (let i = 0; i < 8; i++) {
		cap.push(await newSession(uid2));
		await new Promise((ok) => setTimeout(ok, 2)); // scores distintos
	}
	const alive = await Promise.all(cap.map((x) => r.exists(`session:${x}`)));
	check(
		"8 creates -> el zset queda en 5",
		await r.zcard(`user:${uid2}:sessions`),
		5,
	);
	check("sobreviven las 5 mas nuevas", alive, [0, 0, 0, 1, 1, 1, 1, 1]);

	console.log("\n--- logout puntual ---");
	await h.deleteSession(s1);
	check("deleteSession borra la sesion", await r.exists(`session:${s1}`), 0);
	check(
		"deleteSession limpia el zset",
		await r.zcard(`user:${uid}:sessions`),
		0,
	);
	check("ya no refresca", await h.touchSession(s1), null);
} catch (err) {
	failures++;
	console.log("FAIL  excepcion");
	console.error(err);
} finally {
	for (const x of hashes) await r.del(`session:${x}`);
	for (const u of [uid, uid2]) await r.del(`user:${u}:sessions`);
	r.disconnect();
}

console.log(
	failures === 0
		? "\nINTEGRATION: todo OK"
		: `\nINTEGRATION: ${failures} fallo(s)`,
);
process.exit(failures === 0 ? 0 : 1);
