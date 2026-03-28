import { userService } from "../src/service";

describe("pm engineering", () => {
  it("uses the service layer", () => {
    expect(userService()).toBe("layered");
  });
});

