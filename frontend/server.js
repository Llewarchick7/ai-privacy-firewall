const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, 'public')));

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'frontend' });
});

app.listen(PORT, () => {
  console.log(`Frontend running at http://localhost:${PORT}`);
});
