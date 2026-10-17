// Prueba end-to-end de /api/auth/refresh contra un Redis real.
//
//   REFRESH_REUSE_INTERVAL_SECONDS=2 tsx --env-file=.env itest-refresh.ts
//
// Reproduce el bug de produccion: F5 repetidos mandan el mismo refresh token
// varias veces (en paralelo o con el Set-Cookie de la respuesta perdido) y el
// back lo tomaba como robo y borraba todas las sesiones.
import { randomUUID } from "node:crypto";
import cookieParser from "cookie-parser";
import express from "express";
import { handleRefreshToken } from "./src/controllers/authController.js";
import { connectRedis } from "./src/dbs/redis.js";
import * as h from "./src/helpers/authHelper.js";

const INTERVAL = Number(process.env.REFRESH_REUSE_INTERVAL_SECONDS ?? 30);
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
		.find((c) => c?.startsWith("jwt=") && c !== "jwt=");
	return { status: res.status, next: jwtCookie?.slice(4) ?? null };
};

/** Simula un login: crea la sesion y devuelve su primer refresh token. */
const login = async (userId: string) => {
	const sid = randomUUID();
	const jti = randomUUID();
	const iat = Math.floor(Date.now() / 1000);
	const token = h.signRefreshToken({
		userId,
		username: "itest",
		sid,
		jti,
		iat,
	});
	await h.createSession({
		userId,
		sid,
		tokenHash: h.hashRefreshToken(token),
		jti,
		iat,
	});
	return { sid, token };
};

const uid = `itest-refresh-${Date.now()}`;

try {
	await r.ping();
	const a = await login(uid);
	const b = await login(uid); // otra sesion del mismo usuario (otro dispositivo)

	console.log("--- 10 refresh concurrentes con el mismo token ---");
	const burst = await Promise.all(
		Array.from({ length: 10 }, () => refresh(a.token)),
	);
	check(
		"todas responden 200",
		burst.every((x) => x.status === 200),
		true,
	);
	const t2 = burst[0]?.next as string;
	check(
		"todas reciben el MISMO token nuevo",
		burst.every((x) => x.next === t2),
		true,
	);
	check("el token nuevo es distinto del viejo", t2 !== a.token, true);

	console.log("\n--- F5: el Set-Cookie se perdio, vuelve el token viejo ---");
	const again = await refresh(a.token);
	check(
		"token viejo dentro del intervalo -> 200 con T2",
		[again.status, again.next === t2],
		[200, true],
	);

	console.log("\n--- el cliente sigue normal con T2 ---");
	const step = await refresh(t2);
	check("T2 rota normal", step.status, 200);
	const t3 = step.next as string;

	console.log(
		`\n--- reuso real: token viejo pasado el intervalo (${INTERVAL}s) ---`,
	);
	await new Promise((ok) => setTimeout(ok, (INTERVAL + 1) * 1000));
	check(
		"T2 (previous) fuera del intervalo -> 403",
		(await refresh(t2)).status,
		403,
	);
	check("se revoco esa sesion", await r.exists(`session:${a.sid}`), 0);
	check("T3 ya no refresca", (await refresh(t3)).status, 403);
	check(
		"la otra sesion del usuario sigue viva",
		(await refresh(b.token)).status,
		200,
	);

	console.log(
		`\nE2E REFRESH: ${failures === 0 ? "todo OK" : `${failures} FALLAS`}`,
	);
} catch (err) {
	failures++;
	console.error(err);
} finally {
	for (const sid of await r.zrange(`user:${uid}:sessions`, 0, -1))
		await r.del(`session:${sid}`);
	await r.del(`user:${uid}:sessions`);
	server.close();
	r.disconnect();
	process.exitCode = failures === 0 ? 0 : 1;
}
