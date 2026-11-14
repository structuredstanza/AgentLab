import { describe, expect, it } from "vitest";

import { edgeAccent } from "@/components/exploration-graph";

describe("edgeAccent", () => {
  it("accents an edge whose source intent is done", () => {
    expect(edgeAccent("done", false)).toEqual({ animated: false, strokeWidth: 2.5, strokeOpacity: 1 });
  });

  it("animates toward a live target without accenting", () => {
    expect(edgeAccent("open", true)).toEqual({ animated: true, strokeWidth: 2, strokeOpacity: 0.9 });
  });

  it("lets a live target win over a done source", () => {
    expect(edgeAccent("done", true)).toEqual({ animated: true, strokeWidth: 2, strokeOpacity: 0.9 });
  });

  it("keeps the plain stroke when neither applies", () => {
    expect(edgeAccent("running", false)).toEqual({ animated: false, strokeWidth: 2, strokeOpacity: 0.55 });
    expect(edgeAccent(undefined, false)).toEqual({ animated: false, strokeWidth: 2, strokeOpacity: 0.55 });
  });
});
