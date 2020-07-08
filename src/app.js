const express = require('express');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(require('./controllers/auth-controller'));

module.exports = app;
