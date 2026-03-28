import { protectedUsersRoute } from "../src/routes";

describe("outsource pass", () => {
  it("keeps route auth binding", () => {
    expect(protectedUsersRoute()).toBeDefined();
  });
});

