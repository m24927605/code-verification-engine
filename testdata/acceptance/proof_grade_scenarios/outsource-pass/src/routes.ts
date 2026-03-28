import { authMiddleware } from "./auth";

export function protectedUsersRoute() {
  return authMiddleware;
}

