import wilsoonConfig from '@wilsoon/eslint-config/eslint';

export default [
  { ignores: ['**/dist/', '**/node_modules/', '**/.turbo/'] },
  ...wilsoonConfig,
  {
    // Its autofix turns `beforeAll(async () => { idp = await start(); })` into an arrow that returns the assignment, which vitest types as a cleanup callback and refuses.
    files: ['**/test/**'],
    rules: { 'local/concise-arrow-body': 'off' }
  }
];
