import { authMiddleware } from "./auth";

export function protectedRoute() {
  return authMiddleware;
}

