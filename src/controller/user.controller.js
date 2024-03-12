import { asyncHandler } from "../../utils/asyncHandler.js";
import { ApiError } from "../../utils/apiError.js";
import {User} from "../models/user.model.js"
import { uploadOnCloudinary } from "../../utils/cloudinary.js";
import { ApiResponse } from "../../utils/apiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshToken = async(userId) => {
    try {
        const user = await User.findById(userId)
        console.log("user found")
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()
        console.log("generated")

        user.refreshToken = refreshToken
        await user.save({validateBeforeSave: false})

        return {accessToken,refreshToken}

    } catch (error) {
        throw new ApiError(500,"Something went wrong while generating access and refresh token")
    }
}

const registerUser = asyncHandler(async (req,res)=>{
    // get user details from frontend
    // validation - not empty
    // check if user already exists: username,email
    // check for image, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res

    const {fullName,email,password,username} = req.body
    console.log("email: ",email);

    if([fullName,email,password,username].some((field)=> field?.trim() ==="")){
        throw new ApiError(400,"all fields are required")
    }

    const existingUser = await User.findOne({
        $or: [{email},{username}]
    })
    if(existingUser){
        throw new ApiError(409,"User with email or username already exists")
    }

    // console.log(req.files)
    // multer files and file name with index 0 as property of multer and then that file path
    const avatarLocalPath = req.files?.avatar[0]?.path;
    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
     coverImageLocalPath = req.files.coverImage[0].path;
    }

    if(!avatarLocalPath){
        throw new ApiError(400,"avatar file is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if(!avatar){
        throw new ApiError(400,"Avatar file is required")
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if(!createdUser){
        throw new ApiError(500,"Something went wrong while registering the user")
    }

    return res.status(201).json(
        new ApiResponse(200,createdUser,"User registered successfully")
    )
})

const loginUser = asyncHandler(async (req,res) =>{
    // req -> data
    // username or email
    // find the user
    // password check
    // acess and refresh token
    // sedn cookies
    console.log(req.body)
    const {username,email,password} = req.body

    if(!(username || email)){
        throw new ApiError(400,"username or email is required")
    }

    const user = await User.findOne({
        $or: [{username},{email}]
    })

    if(!user){
        throw new ApiError(400,"user does not exist")
    }

    const isPasswordValid = user.isPasswordCorrect(password)

    if(!isPasswordValid){
        throw new ApiError(400,"Invalid user credentials")
    }
    
    const {accessToken,refreshToken} = generateAccessAndRefreshToken(user._id)
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("acessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new ApiResponse(
            200,{
                user: loggedInUser,accessToken,refreshToken
            },
            "user logged in successfully"
        )
    )


})

const logoutUser = asyncHandler( async(req,res) =>{
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }
    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(new ApiResponse(201,{},"User logged Out"))
})

const refreshAccessToken = asyncHandler( async(req,res) =>{
    try {
        const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
    
        if(!incomingRefreshToken){
            throw new ApiError(401,"unauthorized request")
        }
    
        const decodedToken = jwt.verify(refreshAccessToken,process.env.REFRESH_TOKEN_SECRET)
    
        const user = findById(decodedToken?._id)
    
        if(!user){
            throw new ApiError(401,"invalid refresh token")
        }
        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(401,"refresh token is expired or used")
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
    
        const {accessToken,newRefreshToken} = generateAccessAndRefreshToken(user._id)
    
        res
        .status(200)
        .cookie("accessToken",accessToken,options)
        .cookie("refreshToken",newRefreshToken,options)
        .json(
            ApiResponse(
                201,
                {accessToken,refreshToken : newRefreshToken},
                "Access token refreshed"
            )
        )
    } catch (error) {
        throw new ApiError(401,error?.message || "Invalid refresh Token")
    }
})

export {registerUser,loginUser,logoutUser,refreshAccessToken}