import "@testing-library/jest-dom/vitest";
import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("next-intl", () => ({ useTranslations: () => (key: string) => key }));

import { FindingScreenshots } from "@/app/(main)/function/findings/_components/finding-screenshots";

afterEach(cleanup);

const path = "tasks/7/screenshots/shot.png";
const href = "/api/workspace/download?path=tasks%2F7%2Fscreenshots%2Fshot.png";

describe("FindingScreenshots", () => {
  it("links the path and renders a thumbnail under 1 MB", () => {
    const { container } = render(<FindingScreenshots items={[{ path, size: 2048 }]} />);
    const link = container.querySelector("a");
    expect(link).toHaveAttribute("href", href);
    expect(link).toHaveTextContent("shot.png");
    expect(container.querySelector("img")).toHaveAttribute("src", href);
  });

  it("links without a thumbnail at 1 MB or more", () => {
    const { container } = render(<FindingScreenshots items={[{ path, size: 1 << 20 }]} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("a")).toHaveAttribute("href", href);
  });

  it("renders nothing without screenshots", () => {
    const { container } = render(<FindingScreenshots />);
    expect(container).toBeEmptyDOMElement();
  });
});
