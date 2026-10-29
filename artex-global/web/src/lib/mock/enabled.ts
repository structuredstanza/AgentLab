// Mock toggle. A public variable injected at build time (only readable in the browser with the NEXT_PUBLIC_ prefix).
// Setting NEXT_PUBLIC_MOCK=1 on Vercel makes the whole site use mock data, with no backend required.
export const MOCK = process.env.NEXT_PUBLIC_MOCK === "1";
