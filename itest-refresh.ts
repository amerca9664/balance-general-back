// Prueba end-to-end de /api/auth/refresh y /logout contra un Redis real.
//
//   tsx --env-file=.env itest-refresh.ts
//
// Reproduce el bug de produccion: F5 repetidos mandan el mismo token varias
// veces (en paralelo, con la respuesta perdida o tras un 429) y el back lo
// tomaba como robo y cerraba la sesion. Con el token de sesion sin rotacion
// todas esas requests son equivalentes.
import cookieParser from "cookie-parser";
import express from "express";
import {
	handleRefreshToken,
	logoutController,
} from "./src/controllers/authController.js";
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

const app = express();
app.use(cookieParser());
app.post("/api/auth/refresh", handleRefreshToken);
app.post("/api/auth/logout", logoutController);
const server = app.listen(0);
const port = (server.address() as { port: number }).port;

/** Un POST "del navegador" con la cookie de sesion. */
const post = async (path: string, token: string) => {
	const res = await fetch(`http://127.0.0.1:${port}/api/auth/${path}`, {
		method: "POST",
		headers: { cookie: `jwt=${token}` },
	});
	const body = (await res.json()) as { token?: string };
	const cookie = res.headers
		.getSetCookie()
		.map((c) => c.split(";")[0])
		.find((c) => c?.startsWith("jwt="));
	return {
		status: res.status,
		accessToken: body.token ?? null,
		cookie: cookie?.slice(4) ?? null,
	};
};

/** Simula un login: crea la sesion y devuelve su token. */
const login = async (userId: string) => {
	const token = h.generateSessionToken();
	await h.createSession({
		userId,
		username: "itest",
		tokenHash: h.hashSessionToken(token),
	});
	return token;
};

const uid = `itest-refresh-${Date.now()}`;

try {
	await r.ping();
	const a = await login(uid);
	const b = await login(uid); // otra sesion del mismo usuario (otro dispositivo)

	console.log("--- 10 refresh concurrentes con el mismo token ---");
	const burst = await Promise.all(
		Array.from({ length: 10 }, () => post("refresh", a)),
	);
	check(
		"todas responden 200 con access token",
		burst.every((x) => x.status === 200 && x.accessToken),
		true,
	);
	check(
		"la cookie no cambia (sin rotacion)",
		burst.every((x) => x.cookie === a),
		true,
	);

	console.log("\n--- respuesta perdida / 429: el mismo token, mas tarde ---");
	await new Promise((ok) => setTimeout(ok, 3000));
	check("el token sigue sirviendo", (await post("refresh", a)).status, 200);

	console.log("\n--- logout ---");
	check("logout -> 200", (await post("logout", a)).status, 200);
	check("tras logout no refresca", (await post("refresh", a)).status, 403);
	check(
		"la otra sesion del usuario sigue viva",
		(await post("refresh", b)).status,
		200,
	);
	check(
		"token inventado -> 403",
		(await post("refresh", h.generateSessionToken())).status,
		403,
	);

	console.log(
		`\nE2E REFRESH: ${failures === 0 ? "todo OK" : `${failures} FALLAS`}`,
	);
} catch (err) {
	failures++;
	console.error(err);
} finally {
	for (const x of await r.zrange(`user:${uid}:sessions`, 0, -1))
		await r.del(`session:${x}`);
	await r.del(`user:${uid}:sessions`);
	server.close();
	r.disconnect();
	process.exitCode = failures === 0 ? 0 : 1;
}
