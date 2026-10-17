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
const attacker = `itest-attacker-${tag}`;
const sids: string[] = [];

/** Crea una sesion de prueba y devuelve su sid. */
const newSession = async (userId: string, tokenHash: string) => {
	const sid = `itest-sid-${tag}-${sids.length}`;
	sids.push(sid);
	await h.createSession({ userId, sid, tokenHash, jti: "jti-0", iat: 1 });
	return sid;
};

const rotate = (userId: string, sid: string, from: string, to: string) =>
	h.refreshSession({
		userId,
		sid,
		tokenHash: h.hashRefreshToken(from),
		nextHash: h.hashRefreshToken(to),
		nextJti: `jti-${to}`,
		nextIat: 100,
	});

try {
	await r.ping();

	console.log("--- create ---");
	const sid = await newSession(uid, h.hashRefreshToken("tok1"));
	check("la sesion existe", await r.hget(`session:${sid}`, "userId"), uid);
	check("session: tiene TTL > 0", (await r.ttl(`session:${sid}`)) > 0, true);
	check(
		"zset del usuario tiene el sid",
		await r.zrange(`user:${uid}:sessions`, 0, -1),
		[sid],
	);

	console.log("\n--- rotacion ---");
	check(
		"tok1 (current) rota",
		(await rotate(uid, sid, "tok1", "tok2")).status,
		"rotated",
	);
	check(
		"tok1 (previous) dentro del intervalo -> devuelve el vigente",
		await rotate(uid, sid, "tok1", "tokX"),
		{ status: "reused-in-interval", jti: "jti-tok2", iat: 100 },
	);
	check(
		"el reuso en intervalo no roto nada",
		await r.hget(`session:${sid}`, "current"),
		h.hashRefreshToken("tok2"),
	);

	console.log("\n--- pertenencia cruzada ---");
	check(
		"userId ajeno -> not-found",
		(await rotate(attacker, sid, "tok2", "tok9")).status,
		"not-found",
	);
	check(
		"la sesion de la victima queda intacta",
		await r.exists(`session:${sid}`),
		1,
	);
	check(
		"sid inexistente -> not-found",
		(await rotate(uid, "nunca", "tok2", "tok9")).status,
		"not-found",
	);

	console.log("\n--- reuso real ---");
	const other = await newSession(uid, h.hashRefreshToken("otro1"));
	check(
		"tok2 rota a tok3",
		(await rotate(uid, sid, "tok2", "tok3")).status,
		"rotated",
	);
	check(
		"tok1 (ya ni siquiera previous) -> reuse",
		(await rotate(uid, sid, "tok1", "tokY")).status,
		"reuse-detected",
	);
	check("se borro esa sesion", await r.exists(`session:${sid}`), 0);
	check(
		"tok3 ya no refresca",
		(await rotate(uid, sid, "tok3", "tokZ")).status,
		"not-found",
	);
	check(
		"la OTRA sesion del usuario sobrevive",
		await r.exists(`session:${other}`),
		1,
	);
	check(
		"zset solo con la otra",
		await r.zrange(`user:${uid}:sessions`, 0, -1),
		[other],
	);

	console.log("\n--- cap de sesiones ---");
	const cap: string[] = [];
	for (let i = 0; i < 8; i++)
		cap.push(await newSession(uid2, h.hashRefreshToken(`cap-${i}`)));
	const alive = await Promise.all(cap.map((s) => r.exists(`session:${s}`)));
	check(
		"8 creates -> el zset queda en 5",
		await r.zcard(`user:${uid2}:sessions`),
		5,
	);
	check("sobreviven las 5 mas nuevas", alive, [0, 0, 0, 1, 1, 1, 1, 1]);

	console.log("\n--- logout puntual ---");
	await h.deleteSession(uid, other);
	check("deleteSession borra la sesion", await r.exists(`session:${other}`), 0);
	check(
		"deleteSession limpia el zset",
		await r.zcard(`user:${uid}:sessions`),
		0,
	);
} catch (err) {
	failures++;
	console.log("FAIL  excepcion");
	console.error(err);
} finally {
	for (const s of sids) await r.del(`session:${s}`);
	for (const u of [uid, uid2, attacker]) await r.del(`user:${u}:sessions`);
	r.disconnect();
}

console.log(
	failures === 0
		? "\nINTEGRATION: todo OK"
		: `\nINTEGRATION: ${failures} fallo(s)`,
);
process.exit(failures === 0 ? 0 : 1);
