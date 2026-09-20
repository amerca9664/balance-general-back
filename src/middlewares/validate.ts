import type { NextFunction, Request, Response } from "express";

export const validate =
	(schema) => (req: Request, res: Response, next: NextFunction) => {
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
	(schema) => (req: Request, res: Response, next: NextFunction) => {
		try {
			req.query = schema.parse(req.query);
			next();
		} catch (error) {
			return res.status(400).json({
				success: false,
				errors: error,
			});
		}
	};
