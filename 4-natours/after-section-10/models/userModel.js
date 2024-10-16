const AppError = require('../utils/apiError');
const catchAsync = require('../utils/catchAsync');
const sendEmail = require('../utils/email');
const User = require('./../models/usersModel');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');  //to asynchronous the sync function
const globalErroHandler = require('./errorController');
const crypto = require('crypto'); 

const signInToken = id =>{
    return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
})
};

exports.signup = catchAsync(async (req, res, next)=>{
const newUser = await User.create(req.body); //another way of getting details
/* const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    confirmPassword: req.body.confirmPassword,
    changedPasswordAt: req.body.changedPasswordAt
}); */ //if we use this code then we can access only those fields which we are requesting here
const token = signInToken(newUser._id);
// const token = jwt.sign({id: newUser._id}, process.env.JWT_SECRET, {
//     expiresIn: process.env.JWT_EXPIRES_IN })


res.status(201).json({
    status:'success',
    token,
    data:{
        user: newUser
    }
});
});

exports.login = catchAsync(async(req,res,next)=>{
    const {email, password} = req.body;

    //1)Check if email and password are exist
    if(!email || !password) return next(new AppError(`Please provide email and password`, 400));

    //2)Check if user exist and password is correct
    const user = await User.findOne({email}).select('+password');
    //console.log(user);

    //Pass12245 == $2b$12$vubDP0GCNcoSvsxAU0FHDeNWLGccFo6WCUSZ5dQHCBZYiBxev1qjW 
    //how to compare this?? code written in usersmodel.js

    //const correct = await user.correctPassword(password, user.password); // this method will return promise and if user does not exist then it will not work

    if(!user || !await user.correctPassword(password, user.password)){
        return next(new AppError(`The username and password are incorrect.`, 401));
    }

    //3) if everything is ok send token to client
    const token =signInToken(user._id);
    res.status(200).json({
        status: "success",
        token,

    })

});

exports.protect = catchAsync( async (req, res, next)=>{
    //1)Getting token and check of it's there
    let token;
    if(req.headers.authorization && req.headers.authorization.startsWith("Bearer") ){
          token = req.headers.authorization.split(' ')[1];
    }
    
    //2)Verification of token
    if(!token){
        return next( new AppError(`You are not logged in. Please login to get access`,401))
    }

    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);  //to make function asynchronous as jwt.verify(token, process.env.JWT_SECRET) is sync function and we are taking it in async so need to convert it in async function
    //console.log(decoded);

    //3)Check if user still exists
    const currentUser = await User.findById(decoded.id);
    //console.log(currentUser);
    if(!currentUser){
        return next(new AppError(`The user is no longer exist for a token.Please login again`, 401));
    }
    // console.log(currentUser.correctPasswordAfter(decoded.iat));
    //4)Check if user changed password after JWT was issued
     if(currentUser.correctPasswordAfter(decoded.iat)) {
        return  next( new AppError(`The user recently changed the password, Please login again`, 401) );
     }

     //Grantaccess to user
     req.user = currentUser;

    next();
});

//here we want to pass arguments in middleware function sothis is how we pass the arguments
exports.restrictTo = (...roles) =>{  //roles is an array e.g
    return (req, res, next)=>{
        if(!roles.includes(req.user.role)){  //stroring current user on req.user is mimp here which we didi in protect function
            return next(new AppError(`You are not authorized to perform this action`, 403));
        }

        next();

    }
}

exports.forgotPassword =catchAsync( async (req, res, next)=>{

    //1) Get user based on POST mail id
    const user = await User.findOne({email: req.body.email})
    if(!user){
        return next(new AppError(`There is no user with email address`, 401));
    }
    //2) Generate the random reset token 
    const resetToken = user.createPasswordResetToken();
    await user.save({validateBeforeSave: false});

    //3) send reset link to user's email
    const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/resetPassword/${resetToken}`;

    const message = `Forgot your password? Submit a patch request with a new password and password confirm at:\n ${resetURL}.\n If you didn't forgot your password ignore this email.`;

    try{
    await sendEmail({
        email: user.email,
        subject: "Your password reset token (Vaid for 10 min).",
        message,  
    });

    res.status(200).json({
        status: 'success',
        message: 'Token sent succesfully'
    });

    }
    catch(err){
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({validateBeforeSave: false});
        return next(new AppError(`There was error while sending an email. Please try again later.`, 500))

    }
});

exports.resetPassword =catchAsync(async (req, res, next)=>{
    
     //1) get user based on token
        //Note inour database we have stored encrypted token
    const hashToken = crypto.createHash('sha256').update(req.params.token).digest('hex'); //this is encrypted token
    //console.log(hashToken);
    const user = await User.findOne({passwordResetToken: hashToken, passwordResetExpires:{$gt: Date.now()}});
//    console.log(user);
    //2) if token has not expired and there is user then set password
    if(!user){
        return next(new AppError("Your token is not valid or expired", 400));
    }
    user.password = req.body.password;
    user.confirmPassword = req.body.confirmPassword;
    user.passwordResetToken = undefined;  //deleting this passwordResetToken after setting new password 
    user.passwordResetExpires = undefined;
    await user.save({validateBeforeSave: true}); //here we haveto use validator to verify password

    //3) update changedPasswordAt property for the user
            //this code is written in models

    //4) log the user in, send JWT token
    const token =signInToken(user._id);
    // console.log("Token: "+ token);
    res.status(200).json({
        status: "success",
        token,

    })

});
