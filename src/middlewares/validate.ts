import type { NextFunction, Request, Response } from "express";
import type { ZodType } from "zod";

export const validate =
	(schema: ZodType) => (req: Request, res: Response, next: NextFunction) => {
		try {
			schema.parse(req.body);
			next();
		} catch (error) {
			return res.status(400).json({
				success: false,
				errors: error,
			});
		}
	};

export const validateQuery =
	(schema: ZodType) => (req: Request, res: Response, next: NextFunction) => {
		try {
			schema.parse(req.query);
			next();
		} catch (error) {
			return res.status(400).json({
				success: false,
				errors: error,
			});
		}
	};
