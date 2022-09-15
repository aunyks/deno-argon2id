import { Argon2, fromBase64, toBase64, fromBytes, toBytes } from "./argon2.ts";
import {
  assert,
  assertEquals,
} from "https://deno.land/std@0.156.0/testing/asserts.ts";

Deno.test("basic hash", async () => {
  const argon = await Argon2.initialize({
    saltLength: 16,
    outputLength: 32,
  });
  const digest = argon.hash(
    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    toBase64(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
  );
  assertEquals(digest, "tZglyBOAchSOYY9drXmdEoHOTrVeo5A8pt11mc6wueA=");
});

Deno.test("basic verify", async () => {
  const argon = await Argon2.initialize({
    saltLength: 16,
    outputLength: 32,
  });
  assert(
    argon.verify(
      "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
      "tZglyBOAchSOYY9drXmdEoHOTrVeo5A8pt11mc6wueA=",
      toBase64(
        new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
      ),
    ),
  );
});

Deno.test("from / to bytes", () => {
  const data = [0, 1, 2, 3, 9, 8, 7, 5]
  assertEquals(
    data,
    toBytes(fromBytes(data)),
  );
});

Deno.test("from / to base64", () => {
  const data = [0, 1, 2, 3, 9, 8, 7, 5]
  assertEquals(
    data,
    fromBase64(toBase64(data)),
  );
});

