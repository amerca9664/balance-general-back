import bcrypt from "bcrypt";
import type { Request, Response } from "express";
import {
	clearRefreshCookie,
	createSession,
	deleteAllSessions,
	deleteSessionByHash,
	existingLoginTokenReuseLogic,
	type GraceSession,
	getSessionByHash,
	hashRefreshToken,
	type RefreshTokenPayload,
	registerJti,
	resolveGraceReplay,
	rotateSession,
	SALT_ROUNDS,
	setjti,
	setRefreshCookie,
	signAccessToken,
	signRefreshToken,
	verifyRefreshToken,
} from "../helpers/authHelper.js";
import { User } from "../models/users.js";

export const loginController = async (req: Request, res: Response) => {
	try {
		const { email, password } = req.body;
		const cookieRefreshToken = req.cookies?.jwt;

		const user = await User.findOne({ email });
		if (!user) {
			return res
				.status(401)
				.json({ success: false, message: "Credenciales inválidas" });
		}

		const isMatch = await bcrypt.compare(password, user.password);
		if (!isMatch) {
			return res
				.status(401)
				.json({ success: false, message: "Credenciales inválidas" });
		}

		if (cookieRefreshToken) {
			// La busqueda es por el hash de la cookie: no hace falta confiar en
			// nada que diga el JWT para saber si esa sesion existe.
			await existingLoginTokenReuseLogic(cookieRefreshToken);
			clearRefreshCookie(res);
		}

		const accessToken = signAccessToken(user._id, user.email);

		const jti = crypto.randomUUID(); // Genera un identificador único para el token

		const newRefreshToken = signRefreshToken(String(user._id), user.email, jti);

		await createSession({
			userId: String(user._id),
			tokenHash: hashRefreshToken(newRefreshToken),
		});

		setRefreshCookie(res, newRefreshToken);
		setjti(res, jti); // Establece la cookie con el identificador único del token

		return res.status(200).json({
			success: true,
			message: "ok",
			token: accessToken,
			username: user.username,
		});
	} catch (_error) {
		console.error(_error);
		return res
			.status(500)
			.json({ success: false, message: "Error interno del servidor" });
	}
};

export const registerController = async (req: Request, res: Response) => {
	try {
		const { username, email, password } = req.body;

		const existingUser = await User.findOne({ email });
		if (existingUser) {
			return res
				.status(409)
				.json({ success: false, message: "El email ya está registrado" });
		}

		const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

		const newUser = await User.create({
			username,
			email,
			password: hashedPassword,
		});

		return res.status(201).json({
			success: true,
			message: "Usuario registrado",
			data: { id: newUser._id },
		});
	} catch (_error) {
		console.error(_error);
		return res
			.status(500)
			.json({ success: false, message: "Error interno del servidor" });
	}
};

/**
 * Replay dentro de la ventana de gracia: reenvia el par de cookies vigente
 * (el mismo que emitio la rotacion original) y un access token nuevo.
 *
 * Es idempotente: no rota ni cambia nada en Redis, asi que dos requests que
 * rescaten al mismo cliente desfasado reciben exactamente el mismo token y
 * el cookie jar termina consistente sin importar el orden en que lleguen.
 */
const replyWithGraceSession = (
	res: Response,
	grace: GraceSession,
	decoded: RefreshTokenPayload,
) => {
	setRefreshCookie(res, grace.token);
	setjti(res, grace.jti);

	const accessToken = signAccessToken(decoded.id, decoded.username);

	return res
		.status(200)
		.json({ success: true, message: "ok", token: accessToken });
};

export const handleRefreshToken = async (req: Request, res: Response) => {
	try {
		const cookieRefreshToken = req.cookies?.jwt;
		if (!cookieRefreshToken) {
			return res
				.status(401)
				.json({ success: false, message: "Falta refresh token" });
		}

		const previousHash = hashRefreshToken(cookieRefreshToken);

		// Firma primero: sin un payload verificado no hay a quien atribuirle el
		// token, y un token basura tampoco tiene por que quemar un jti.
		const decoded = verifyRefreshToken(cookieRefreshToken);
		if (!decoded?.id) {
			clearRefreshCookie(res);
			return res
				.status(403)
				.json({ success: false, message: "Refresh token inválido" });
		}

		const sessionUserId = await getSessionByHash(previousHash);

		if (sessionUserId && sessionUserId !== decoded.id) {
			// La sesion dice pertenecer a otro usuario que el token firmado.
			// Misma politica que la reuse: se revocan todos los tokens del
			// dueno del token presentado.
			console.log("🚨 ¡Refresh token de otro usuario detectado!");
			await deleteAllSessions(decoded.id);
			clearRefreshCookie(res);
			return res
				.status(403)
				.json({ success: false, message: "Refresh token manipulado" });
		}

		if (!sessionUserId) {
			// El JWT verifica pero ese hash ya no esta activo: o nunca lo
			// emitimos, o ya fue rotado.
			//
			// Primero la gracia: si la rotacion fue hace segundos, lo mas
			// probable es el propio cliente cuyo Set-Cookie se perdio (F5 con
			// la request en vuelo), no un robo. Se le devuelve el token
			// vigente y listo.
			const grace = await resolveGraceReplay({
				previousHash,
				decodedId: decoded.id,
			});
			if (grace) {
				console.log("Gracia: cliente resincronizado con el token vigente.");
				return replyWithGraceSession(res, grace, decoded);
			}

			// Con Redis esto NO es el vencimiento normal, porque el `EX` de la
			// clave y el `exp` del JWT se fijaron en el mismo momento: si el
			// JWT esta vivo, la clave tambien. Huele a replay => nuke.
			console.log("🚨 ¡Intento de reutilización de Refresh Token detectado!");
			await deleteAllSessions(decoded.id);
			console.log(
				`🔒 Todas las sesiones invalidadas para: ${decoded.username ?? decoded.id}.`,
			);
			clearRefreshCookie(res);
			return res
				.status(403)
				.json({ success: false, message: "Refresh token inválido" });
		}

		// La sesion esta activa y es del dueño del token: rotacion en curso.
		// El dedup por jti evita que dos requests concurrentes del mismo
		// cliente intenten rotar el mismo token.
		const cookieJti = req.cookies?.jti;
		const registered = await registerJti({
			jti: cookieJti,
			tokenHash: previousHash,
		});

		if (!registered) {
			// El jti ya existe: otra request del mismo cliente esta rotando
			// este token ahora mismo. NO se vuelve a rotar y NO se tocan las
			// cookies: el front reintenta en un segundo y a esa altura o el
			// ganador ya escribio la gracia (replay 200) o la rotacion ya
			// termino y el retry entra por el camino normal.
			return res
				.status(409)
				.json({ success: false, message: "Refresh token ya usado" });
		}

		// Si la rotacion no llega a completarse, ninguna salida posterior deja
		// viva la cookie vieja (incluidas las de error y el 500): pasa por
		// clearRefreshCookie y no por un literal, porque el `path` tiene que
		// ser identico al del setRefreshCookie() del final (los dos comparten
		// COOKIE_OPTIONS adentro del helper); si divergen, el clear no borra
		// nada y el token sigue viajando en cada request sin que se note.
		clearRefreshCookie(res);

		const accessToken = signAccessToken(decoded.id, decoded.username);

		// Rotacion: el token viejo se borra y el nuevo toma su lugar en el
		// indice, con un `jti` distinto que garantiza un hash distinto.

		const newJti = crypto.randomUUID(); // Genera un identificador único para el token
		const nextRefreshToken = signRefreshToken(
			decoded.id,
			decoded.username ?? "",
			newJti,
		);
		const nextHash = hashRefreshToken(nextRefreshToken);

		const rotated = await rotateSession({
			userId: decoded.id,
			previousHash,
			nextHash,
			nextToken: nextRefreshToken,
			nextJti: newJti,
		});

		if (!rotated) {
			// Perdio la carrera el CAS. NO es robo y por eso NO se nukea: el
			// token matcheo en Redis hace un instante, asi que era valido y lo
			// unico que paso es que otro request del MISMO cliente lo rotó
			// primero (doble pestaña, retry, o el intervalo del front).
			// Nuke-all aca te desloguearia de todos tus dispositivos por una
			// carrera propia.
			//
			// Ese ganador dejo ademas el puntero de gracia con su token, asi
			// que lo mas probable es poder resincronizar al cliente aca mismo.
			const grace = await resolveGraceReplay({
				previousHash,
				decodedId: decoded.id,
			});
			if (grace) {
				console.log("Rotación perdida: resincronizado con el token vigente.");
				return replyWithGraceSession(res, grace, decoded);
			}

			// Tampoco se vuelve a setear la cookie: la respuesta perdedora puede
			// llegar DESPUES de la ganadora, y su Set-Cookie pisaria el token
			// bueno que acaba de emitir el ganador.
			console.log(
				"Rotación perdida: otro request del mismo cliente ya rotó esto.",
			);
			return res
				.status(403)
				.json({ success: false, message: "Refresh token ya rotado" });
		}

		setRefreshCookie(res, nextRefreshToken);
		setjti(res, newJti); // Establece la cookie con el identificador único del token
		return res
			.status(200)
			.json({ success: true, message: "ok", token: accessToken });
	} catch (_error) {
		console.error(_error);
		return res
			.status(500)
			.json({ success: false, message: "Error interno del servidor" });
	}
};

export const logoutController = async (req: Request, res: Response) => {
	try {
		const cookieRefreshToken = req.cookies?.jwt;
		if (cookieRefreshToken) {
			// Busqueda por hash, como el deleteOne({tokenHash}) original: si el
			// token no esta en Redis no hay nada que borrar, y si esta es
			// porque lo emitimos nosotros para esa sesion.
			const tokenHash = hashRefreshToken(cookieRefreshToken);
			const userId = await getSessionByHash(tokenHash);
			if (userId) {
				await deleteSessionByHash(userId, tokenHash);
			} else {
				// Cookie desfasada (se perdio el Set-Cookie de la ultima
				// rotacion): igual hay que cortar la sesion vigente a la que
				// apunta el puntero de gracia, o el logout no revocaria nada.
				const grace = await resolveGraceReplay({ previousHash: tokenHash });
				if (grace) {
					await deleteSessionByHash(
						grace.userId,
						hashRefreshToken(grace.token),
					);
				}
			}
		}

		clearRefreshCookie(res);

		return res
			.status(200)
			.json({ success: true, message: "Sesión cerrada correctamente" });
	} catch (_error) {
		console.error(_error);
		return res
			.status(500)
			.json({ success: false, message: "Error interno del servidor" });
	}
};

// Ruta protegida: verifyToken ya corrió, asi que req.user existe.
export const meController = (req: Request, res: Response) => {
	if (!req.user) {
		return res.status(401).json({ success: false, message: "No autenticado" });
	}

	return res.status(200).json({ success: true, data: req.user });
};
