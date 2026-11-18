// The image entrypoint is Node; initialization must finish before listening.
import '../scripts/setup.ts';
await import('./index.ts');
