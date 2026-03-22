const express = require('express');
const { itemsRouter } = require('./routes/items');

const app = express();

app.use(express.json());
app.use('/items', itemsRouter);

app.listen(3000, () => {
  console.log('Server running on port 3000');
});

module.exports = app;
