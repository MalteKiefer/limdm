import js from '@eslint/js'
import reactHooks from 'eslint-plugin-react-hooks'
import globals from 'globals'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['node_modules', 'test-results', 'playwright-report', 'src/api/schema.d.ts'] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  reactHooks.configs.flat['recommended-latest'],
  {
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
    rules: {
      // no eval and friends: the console runs under script-src 'self'
      'no-eval': 'error',
      'no-implied-eval': 'error',
      // schemas and DOM roots are checked where they come from; ! documents it
      '@typescript-eslint/no-non-null-assertion': 'off',
      'no-new-func': 'error',
      'no-restricted-syntax': ['error', { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: 'no raw HTML: XSS and CSP' }],
      // zod compiles with new Function unless jitless (src/lib/zod.ts sets it)
      'no-restricted-imports': ['error', { paths: [{ name: 'zod', message: "import { z } from 'src/lib/zod' (jitless under the CSP)", allowTypeImports: true }] }],
    },
  },
  { files: ['src/lib/zod.ts'], rules: { 'no-restricted-imports': 'off' } },
)
