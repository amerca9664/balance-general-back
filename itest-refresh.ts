// Prueba end-to-end de /api/auth/refresh contra un Redis real.
//
//   REFRESH_ROTATION_GRACE_SECONDS=2 tsx --env-file=.env itest-refresh.ts
//
// Reproduce el bug de produccion: F5 repetidos mandan el mismo refresh token
// varias veces (en paralelo o con el Set-Cookie de la respuesta perdido) y el
// back lo tomaba como robo y borraba todas las sesiones.
import cookieParser from "cookie-parser";
import express from "express";
import { handleRefreshToken } from "./src/controllers/authController.js";
import { connectRedis } from "./src/dbs/redis.js";
import * as h from "./src/helpers/authHelper.js";

const GRACE_SECONDS = Number(process.env.REFRESH_ROTATION_GRACE_SECONDS ?? 60);
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

const app = express();
app.use(cookieParser());
app.post("/api/auth/refresh", handleRefreshToken);
const server = app.listen(0);
const port = (server.address() as { port: number }).port;

/** Un refresh "del navegador": manda la cookie y devuelve el token nuevo, si vino. */
const refresh = async (token: string) => {
	const res = await fetch(`http://127.0.0.1:${port}/api/auth/refresh`, {
		method: "POST",
		headers: { cookie: `jwt=${token}` },
	});
	const jwtCookie = res.headers
		.getSetCookie()
		.map((c) => c.split(";")[0])
		.filter((c) => c.startsWith("jwt=") && c !== "jwt=")
		.at(-1);
	return { status: res.status, next: jwtCookie?.slice(4) ?? null };
};

const alive = async (token: string) =>
	(await h.getSessionByHash(h.hashRefreshToken(token))) !== null;

try {
	await r.ping();
	const uid = `itest-refresh-${Date.now()}`;
	const t1 = h.signRefreshToken(uid, "itest", crypto.randomUUID());
	await h.createSession({ userId: uid, tokenHash: h.hashRefreshToken(t1) });

	console.log("--- 10 refresh concurrentes con el mismo token ---");
	const burst = await Promise.all(
		Array.from({ length: 10 }, () => refresh(t1)),
	);
	check(
		"todas responden 200",
		burst.every((b) => b.status === 200),
		true,
	);
	const t2 = burst[0]?.next as string;
	check(
		"todas reciben el MISMO token nuevo",
		burst.every((b) => b.next === t2),
		true,
	);
	check("el token nuevo esta vivo", await alive(t2), true);
	check("una sola sesion en el zset", await r.zcard(`user:${uid}:sessions`), 1);

	console.log("\n--- F5: el Set-Cookie se perdio, vuelve T1 ---");
	for (let i = 0; i < 3; i++) {
		const again = await refresh(t1);
		check(
			`replay ${i + 1} de T1 -> 200 con T2`,
			[again.status, again.next === t2],
			[200, true],
		);
	}

	console.log("\n--- cadena: T2 -> T3, y llega tarde un T1 ---");
	const step = await refresh(t2);
	check("T2 rota normal", step.status, 200);
	const t3 = step.next as string;
	const late = await refresh(t1);
	check(
		"T1 tardio -> 200 con el token vivo (T3)",
		[late.status, late.next === t3],
		[200, true],
	);
	check("T3 sigue vivo (nadie nukeo)", await alive(t3), true);

	console.log(`\n--- reuso real: T1 pasada la gracia (${GRACE_SECONDS}s) ---`);
	await new Promise((ok) => setTimeout(ok, (GRACE_SECONDS + 1) * 1000));
	const stolen = await refresh(t1);
	check("T1 fuera de la gracia -> 403", stolen.status, 403);
	check("se revocaron todas las sesiones (T3 muerto)", await alive(t3), false);
	check("zset vacio", await r.zcard(`user:${uid}:sessions`), 0);
	check("T3 ya no refresca", (await refresh(t3)).status, 403);

	console.log(
		`\nE2E REFRESH: ${failures === 0 ? "todo OK" : `${failures} FALLAS`}`,
	);
} catch (err) {
	failures++;
	console.error(err);
} finally {
	for (const k of await r.keys("rt:*")) {
		const v = await r.get(k);
		if (v?.includes("itest-refresh")) await r.del(k);
	}
	for (const k of await r.keys("user:itest-refresh*:sessions")) await r.del(k);
	server.close();
	r.disconnect();
	process.exitCode = failures === 0 ? 0 : 1;
}
