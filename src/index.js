import { createApp } from './app.js';

const port = Number(process.env.PORT) || 4000;
const app = createApp();

app.listen(port, '0.0.0.0', () => {
  console.log(`API listening on ${port}`);
});
// Updated 08 أفريل, 2026 CET 10:02:45 ص
