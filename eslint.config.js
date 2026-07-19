// Flat ESLint config (ESLint 9 + typescript-eslint 8).
// Currently the non-type-checked recommended set. Enabling
// `recommendedTypeChecked` is tracked as follow-up work; it needs the project
// service wired up for the config files as well as src/ and test/.
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import prettier from "eslint-config-prettier";

export default tseslint.config(
  { ignores: ["dist/**", "coverage/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
    },
  },
  prettier,
);
