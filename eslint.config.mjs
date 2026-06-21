import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  // Lint only the library sources; the template's automation scripts
  // (.github, .hooks, config) carry their own conventions.
  {
    ignores: [
      "coverage/**",
      "node_modules/**",
      ".github/**",
      ".claude/**",
      ".hooks/**",
      "config/**",
      "tests/**",
    ],
  },
  js.configs.recommended,
  {
    files: ["src/**/*.mjs", "test/**/*.mjs"],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      globals: {
        ...globals.node,
      },
    },
    rules: {
      "consistent-return": "error",
    },
  },
);
