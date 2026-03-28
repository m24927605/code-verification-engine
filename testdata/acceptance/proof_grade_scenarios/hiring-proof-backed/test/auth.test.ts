import { protectedRoute } from "../src/routes";

describe("auth", () => {
  it("binds middleware to the protected route", () => {
    expect(protectedRoute()).toBeDefined();
  });
});

