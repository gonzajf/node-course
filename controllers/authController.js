const passport = require('passport');
const mongoose = require('mongoose');
const User = mongoose.model('User');
const crypto = require('crypto');

exports.login = passport.authenticate('local', {

    failureRedirect: '/login',
    failureFlash: 'Failed Login!',
    successRedirect: '/',
    successFlash: 'You are now logged in!'
});

exports.logout = (req, res) => {
    req.logout();
    req.flash('success', 'You are now logged out!');
    res.redirect('/');
}

exports.isLoggedIn = (req, res, next) => {

    if(req.isAuthenticated()) {
        next();
        return; 
    }
    req.flash('error', 'You must be logged in to do that');
    res.redirect('login');
}

exports.forgot = async (req, res) => {
    //see if a user with that email exists
    const user = await User.findOne({email: req.body.email});
    if(!user) {
        req.flash('error', 'A password reset has been emailed to you.');
        return res.redirect('/login');
    }
    //set reset token and expiry on their account
    user.resetPasswordToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordExpires = Date.now() + 3600000; //1 hour from now
    await user.save();
    //send them an email with that token
    const resetUrl = `http://${req.headers.host}/account/reset/${user.resetPasswordToken}`;
    req.flash('success', `A password reset has been emailed to you. ${resetUrl}`);
    //redirect to login page
    res.redirect('/login');
}

exports.reset = async (req, res) => {

    const user = await User.findOne({
        resetPasswordToken: req.params.token,
        resetPasswordExpires: {$gt: Date.now()}
    });
    
    if(!user) {
        req.flash('error', 'Password reset is invalid or has expired.');
        return res.redirect('/login');
    }
    //if there is a user, show the reset password form
    res.render('reset', {title: 'Reset your password!'});
}