import { Request, Response, NextFunction } from "express";

export function generateToken(payload: {
  email: string;
  role?: string;
}): Promise<string>;

export function verifyToken(token: string): { email: string; role?: string };

export function generateSalt(): string;

export function hashPassword(password: string): string;

export function hashWithSalt(password: string, salt: string): string;

export function comparePassword(password: string, hash: string): boolean;

export function middleware(
  request: Request,
  response: Response,
  next: NextFunction
): void;
