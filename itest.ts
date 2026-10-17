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

try {
	await r.ping();

	const uid = `itest-${Date.now()}`;
	const attacker = `itest-attacker-${Date.now()}`;
	const h1 = h.hashRefreshToken("tok1");
	const h2 = h.hashRefreshToken("tok2");
	const h3 = h.hashRefreshToken("tok3");

	console.log("--- create / lookup ---");
	await h.createSession({ userId: uid, tokenHash: h1 });
	check(
		"getSessionByHash(h1) devuelve el userId",
		await h.getSessionByHash(h1),
		uid,
	);
	check(
		"getSessionByHash desconocido -> null",
		await h.getSessionByHash(h.hashRefreshToken("nunca")),
		null,
	);
	check("clave rt: tiene TTL > 0", (await r.ttl(`rt:${h1}`)) > 0, true);
	check(
		"zset del usuario tiene 1 miembro",
		await r.zcard(`user:${uid}:sessions`),
		1,
	);

	console.log("\n--- rotate CAS ---");
	check(
		"rotate h1 -> h2 aceptado",
		await h.rotateSession({ userId: uid, previousHash: h1, nextHash: h2 }),
		true,
	);
	check(
		"rotate repetido (stale) rechazado",
		await h.rotateSession({ userId: uid, previousHash: h1, nextHash: h3 }),
		false,
	);
	check("h1 borrado tras rotar", await h.getSessionByHash(h1), null);
	check("h2 vivo tras rotar", await h.getSessionByHash(h2), uid);
	check(
		"zset sin h1, con h2",
		await r.zrange(`user:${uid}:sessions`, "0", "-1"),
		[h2],
	);
	check("h3 nunca llego a existir", await h.getSessionByHash(h3), null);

	console.log("\n--- pertenencia cruzada ---");
	check(
		"rotate con userId ajeno rechazado",
		await h.rotateSession({
			userId: attacker,
			previousHash: h2,
			nextHash: h.hashRefreshToken("tok4"),
		}),
		false,
	);
	check("token de la victima queda intacto", await h.getSessionByHash(h2), uid);
	check(
		"atacante no tiene sesiones",
		await r.zcard(`user:${attacker}:sessions`),
		0,
	);

	console.log("\n--- cap de sesiones ---");
	const uid2 = `itest2-${Date.now()}`;
	const capHashes: string[] = [];
	for (let i = 0; i < 8; i++) {
		const hash = h.hashRefreshToken(`cap-${i}`);
		capHashes.push(hash);
		await h.createSession({ userId: uid2, tokenHash: hash });
	}
	const aliveness = await Promise.all(
		capHashes.map((x) => h.getSessionByHash(x)),
	);
	const aliveHashes = capHashes.filter((_, i) => aliveness[i] !== null);
	check(
		"8 creates -> el zset queda en 5",
		await r.zcard(`user:${uid2}:sessions`),
		5,
	);
	check("quedan exactamente 5 claves rt:", aliveHashes.length, 5);
	check(
		"sobreviven las 5 mas nuevas",
		capHashes.slice(3).filter((x) => aliveHashes.includes(x)).length,
		5,
	);
	check(
		"murieron las 3 mas viejas",
		capHashes.slice(0, 3).filter((x) => aliveHashes.includes(x)).length,
		0,
	);

	console.log("\n--- logout puntual ---");
	await h.deleteSessionByHash(uid, h2);
	check(
		"deleteSessionByHash borra la clave",
		await h.getSessionByHash(h2),
		null,
	);
	check(
		"deleteSessionByHash limpia el zset",
		await r.zcard(`user:${uid}:sessions`),
		0,
	);

	console.log("\n--- nuke total ---");
	await h.createSession({ userId: uid, tokenHash: h1 });
	await h.createSession({ userId: uid, tokenHash: h2 });
	await h.createSession({ userId: uid, tokenHash: h3 });
	check("3 sesiones creadas", await r.zcard(`user:${uid}:sessions`), 3);
	await h.deleteAllSessions(uid);
	check("nuke borra h1", await h.getSessionByHash(h1), null);
	check("nuke borra h2", await h.getSessionByHash(h2), null);
	check("nuke borra h3", await h.getSessionByHash(h3), null);
	check("nuke vacia el zset", await r.zcard(`user:${uid}:sessions`), 0);
	await h.deleteAllSessions(uid2);
	check("nuke del usuario 2", await r.zcard(`user:${uid2}:sessions`), 0);
	check(
		"nuke alcanza a los 5 sobrevivientes del cap",
		(await Promise.all(capHashes.map((x) => h.getSessionByHash(x)))).filter(
			(x) => x !== null,
		).length,
		0,
	);
} catch (err) {
	failures++;
	console.log("FAIL  excepcion");
	console.error(err);
} finally {
	// Limpieza: tambien barre claves huerfanas de corridas anteriores.
	for (const k of await r.keys("rt:*")) {
		const v = await r.get(k);
		if (v?.startsWith("itest")) await r.del(k);
	}
	for (const k of await r.keys("user:itest*:sessions")) await r.del(k);
	r.disconnect();
}

console.log(
	failures === 0
		? "\nINTEGRATION: todo OK"
		: `\nINTEGRATION: ${failures} fallo(s)`,
);
process.exit(failures === 0 ? 0 : 1);
