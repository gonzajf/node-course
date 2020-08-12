const moogoose = require('mongoose');

exports.loginForm = (req, res) => {
    res.render('login', {title: 'Login'});
}