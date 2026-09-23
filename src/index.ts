import cookieParser from "cookie-parser";
import cors from "cors";
import express, { type Express, type Request, type Response } from "express";
import { connectDb } from "./dbs/mongoDb.js";
import { authRouter } from "./routes/authRoutes.js";

const app: Express = express();
app.use(
	cors({
		origin: process.env.ORIGINS?.split(",") || "http://localhost:5173",
		credentials: true,
	}),
);

const port = process.env.PORT || 3000;

app.use(cookieParser());
app.use(express.json());
connectDb();
app.get("/", (req: Request, res: Response) => {
	res.status(200).send("Hello World!");
});
app.use("/api/auth", authRouter);
app.listen(port, () => {
	console.log(`Server running on port ${port}`);
});
