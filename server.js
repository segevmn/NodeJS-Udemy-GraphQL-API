const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const path = require('path');
const multer = require('multer');
const { createHandler } = require('graphql-http/lib/use/express');
const expressPlayground =
  require('graphql-playground-middleware-express').default;

const multerConfig = require('./config/multerConfig');
const headersConfig = require('./config/headersConfig');
const graphqlSchema = require('./graphql/schema');
const graphqlResolver = require('./graphql/resolvers');
const auth = require('./middleware/auth');
const { clearImage } = require('./utils/clear');

const app = express();

app.use(bodyParser.json()); // application/json
const upload = multer({
  storage: multerConfig.fileStorage,
  fileFilter: multerConfig.fileFilter,
});

app.use(upload.single('image'));
app.use('/images', express.static(path.join(__dirname, 'images')));
app.use(headersConfig.setHeaders);
app.use(auth);

app.put('/post-image', (req, res, next) => {
  if (!req.isAuth) {
    throw new Error('Not authenticated');
  }
  if (!req.file) {
    return res.status(200).json({ message: 'No file provided!' });
  }

  if (req.body.oldPath) {
    clearImage(req.body.oldPath);
  }
  return res
    .status(201)
    .json({ message: 'File stored.', filePath: req.file.path });
});

app.use(
  '/graphql',
  createHandler({
    schema: graphqlSchema,
    rootValue: graphqlResolver,
    graphiql: true,
    context: req => req.context,
    formatError(err) {
      if (!err.originalError) {
        return err;
      }
      const errData = err.originalError.data;
      const errMessage = err.message || 'An error occured';
      const code = err.originalError.code || 500;
      return { message: errMessage, status: code, data: errData };
    },
  })
);

app.get('/playground', expressPlayground({ endpoint: '/graphql' }));

app.use((error, req, res, next) => {
  console.log(error);
  const status = error.statusCode || 500;
  const errMsg = error.message;
  const errData = error.data;

  res.status(status).json({ message: errMsg, data: errData });
});

mongoose
  .connect(
    'mongodb+srv://segevminyan:segevminyan@cluster0.uazlqbd.mongodb.net/messages'
  )
  .then(result => {
    app.listen(8080);
  })
  .catch(err => {
    console.log(err);
  });
