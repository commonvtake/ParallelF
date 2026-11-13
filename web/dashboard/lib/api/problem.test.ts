import { describe, expect, it } from "vitest";

import { describeProblem, parseProblem } from "./problem";

describe("parseProblem", () => {
  it("returns a well-formed problem unchanged", () => {
    const body = { type: "https://parallelf.dev/problems/conflict", title: "Conflict", status: 409, detail: "Taken." };

    expect(parseProblem(409, body)).toEqual(body);
  });

  it.each([
    ["null", null],
    ["a string", "Bad Gateway"],
    ["an unrelated object", { message: "nope" }],
  ])("falls back for %s", (_name, body) => {
    const problem = parseProblem(502, body);

    expect(problem.status).toBe(502);
    expect(problem.title).toBe("The service is unavailable");
  });

  it("distinguishes client errors in the fallback", () => {
    expect(parseProblem(404, null).title).toBe("The request failed");
  });
});

describe("describeProblem", () => {
  it("prefers field messages", () => {
    const problem = {
      type: "t",
      title: "Validation failed",
      status: 422,
      detail: "The project is not valid.",
      errors: [
        { field: "slug", code: "format", message: "Slug is invalid." },
        { field: "name", code: "required" },
      ],
    };

    expect(describeProblem(problem)).toBe("Slug is invalid. name: required");
  });

  it("falls back to detail, then title", () => {
    expect(describeProblem({ type: "t", title: "Conflict", status: 409, detail: "Taken." })).toBe("Taken.");
    expect(describeProblem({ type: "t", title: "Conflict", status: 409 })).toBe("Conflict");
  });
});
