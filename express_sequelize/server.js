const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const upload = require('express-fileupload');

// create express app
const app = express(); 

app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())
app.use(cors());
app.use(upload())
app.use(express.static('public'))

// Configuring the database
const db = require("./models");
db.sequelize.sync();

//require routes
const usersRouter = require('./routes/user.route');
// const mobileRouter = require('./routes/mobile.route');
// const adminRouter = require('./routes/admin.route');
// const home = require('./routes/home.route');

app.use(function(req, res, next) {
	res.setHeader('Access-Control-Allow-Origin', '*');

    // Request methods you wish to allow
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');

    // Request headers you wish to allow
	res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,x-access-token,content-type');
	res.setHeader('Access-Control-Expose-Headers', 'x-access-token');

    // Set to true if you need the website to include cookies in the requests sent
    // to the API (e.g. in case you use sessions)
    res.setHeader('Access-Control-Allow-Credentials', true);
	next();

  });
 
app.use('/user', usersRouter);
// app.use('/mobile', mobileRouter);
// app.use('/admin', adminRouter);
// app.use('/home', home);
// require('./utils/cronJobs');

// define a simple route
app.get('/', (req, res) => {
    res.json('welcome to the world');
});
// catch 404 and forward to error handler
app.use(function(req, res, next) {
    var err = new Error('URL not found');
    err.status = 404;
    next(err);
});

app.use((err, req, res, next) => {
	if (err) {
		const status =
			res.locals.status ||
			err.statusCode ||
			err.status ||
			(err.output && err.output.statusCode) ||
			400;
		return res.status(status).send({ message: err.message });
	}
	return next();
}); 
let port = process.env.SERVER_PORT || 3055
// listen for requests
app.listen(port, () => { 
    console.log(`Server is listening on port ${port}`);
});
