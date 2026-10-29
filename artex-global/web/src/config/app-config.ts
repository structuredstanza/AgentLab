import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

// Browser tab title and search-engine description, used by the static metadata in layout.tsx.
// The title uses a colon instead of an em dash so it reads "product: description".
const META = {
  title: "ARTEX: Autonomous Penetration Testing Console",
  description: "An LLM-driven system console for autonomous penetration testing",
};

export const APP_CONFIG = {
  name: "ARTEX",
  version: packageJson.version,
  copyright: `© ${currentYear}, ARTEX.`,
  meta: META,
};
