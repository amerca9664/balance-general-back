import mongoose from "mongoose";

mongoose.connection.on("connected", () => console.log("connected"));

mongoose.connection.on("disconnected", () => console.log("disconnected"));
mongoose.connection.on("reconnected", () => console.log("reconnected"));

mongoose.connection.on("close", () => console.log("close"));

const connectDb = async () => {
	const mongoUri = process.env.MONGODB_URI;
	try {
		await mongoose.connect(mongoUri as string);
	} catch (error) {
		if (error instanceof Error) {
			console.error(`Error de conexion: ${error.message}`);
		} else {
			console.error(`Error de conexion: ${error}`);
		}
		process.exit(1);
	}
};

export { connectDb };
