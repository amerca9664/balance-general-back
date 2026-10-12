import { Redis } from "ioredis";

// Inicializamos como null pero definimos su tipo explícito
let redisClient: Redis | null = null;

const connectRedis = (): Redis => {
	if (redisClient) {
		return redisClient;
	}

	redisClient = new Redis({
		host: process.env.REDIS_HOST || "127.0.0.1",
		port: parseInt(process.env.REDIS_PORT || "6379", 10),
		username: process.env.REDIS_USER || "default",
		// Solo mandamos AUTH si hay password real. El fallback anterior era un
		// placeholder y contra un Redis local sin `requirepass` el server
		// responde "ERR Client sent AUTH, but no password is set": todo
		// createSession/getSessionByHash rechazaban y /login devolvia 500.
		...(process.env.REDIS_PASSWORD
			? { password: process.env.REDIS_PASSWORD }
			: {}),
		maxRetriesPerRequest: null,
	});

	redisClient.on("connect", () => {
		console.log("Redis: Socket conectado");
	});

	redisClient.on("ready", () => {
		console.log("Redis: ¡Cliente listo para operar!");
	});

	redisClient.on("error", (error: Error) => {
		console.error(`Error de conexion Redis: ${error.message}`);
	});

	return redisClient;
};

const getRedisClient = (): Redis => {
	if (!redisClient) {
		throw new Error(
			"Redis no ha sido inicializado. Llama a connectRedis() primero.",
		);
	}
	return redisClient;
};

export { connectRedis, getRedisClient, Redis };
