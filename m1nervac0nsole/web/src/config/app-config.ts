import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

// Browser tab title and search-engine description, used by the static metadata in layout.tsx.
// The title uses a colon instead of an em dash so it reads "product: description".
const META = {
  title: "m1nervac0nsole: Autonomous Penetration Testing Console",
  description: "An LLM-driven system console for autonomous penetration testing",
};

// Display brand only. Module paths, M1NERVAC0NSOLE_* env variables, the m1nervac0nsole binary and the
// stored m1nervac0nsole_token keep their technical names.
export const APP_CONFIG = {
  name: "m1nervac0nsole",
  version: packageJson.version,
  copyright: `© ${currentYear}, m1nervac0nsole.`,
  logo: { src: "/logo.png" },
  meta: META,
};
