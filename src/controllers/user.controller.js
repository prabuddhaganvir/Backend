import { asyncHandler } from "../utils/asyncHandler.js";

import { ApiError } from "../utils/ApiError.js";

import { User } from "../models/user.model.js"

import { uploadOnCloudinary } from "../utils/cloudinary.js"

import { ApiResponse } from "../utils/ApiResponse.js";

import jwt from "jsonwebtoken"


const generateAccessAndRefreshToken = async(userId) => {
  try {

    const user = await User. findById(userId)
     const accessToken = user.generateAccessToken()
     const refreshToken = user.generateRefreshToken();

     user.refreshToken = refreshToken
    await user.save({ validateBeforeSave:false })


    return {accessToken, refreshToken}
    
  } catch (error) {
    throw new ApiError(500, "something went wrong while generating refresh and access token")
  }
}


const registerUser = asyncHandler(async (req, res, next) => {
  try {
    console.log("registerUser hit");

    const { fullName, email, username, password } = req.body;
    console.log("Body:", req.body);

    if (
      [fullName, email, username, password].some(
        (field) => !field || field.trim() === ""
      )
    ) {
      throw new ApiError(400, "All fields are required");
    }

    const existedUser = await User.findOne({
      $or: [{ username }, { email }],
    });

    if (existedUser) {
      throw new ApiError(409, "User with email or username already exists");
    }

    console.log("No existing user found");

    const avatarLocalPath = req.files?.avatar?.[0]?.path;

    if (!avatarLocalPath) throw new ApiError(400, "Avatar is required");

    console.log("Avatar local path:", avatarLocalPath);

    const avatar = await uploadOnCloudinary(avatarLocalPath);
    console.log("Avatar uploaded:", avatar);

    const coverImageLocalPath = req.files?.coverImage?.[0]?.path;
    
    const coverImage = coverImageLocalPath
      ? await uploadOnCloudinary(coverImageLocalPath)
      : null;

    let user;
    try {
      user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase(),
      });
    } catch (err) {
      console.error("User creation failed:", err.message);
      throw new ApiError(500, `User creation failed: ${err.message}`);
    }

    const createdUser = await User.findById(user._id).select(
      "-password -refreshTokens"
    );
    if (!createdUser) {
      throw new ApiError(500, "Something went wrong while registering a user");
    }

    console.log("User successfully created");

    return res
      .status(201)
      .json(new ApiResponse(200, createdUser, "User Registered Successfully"));
  } catch (err) {
    console.error("Final error caught:", err);
    next(err);
  }
});

const loginUser = asyncHandler(async (req, res) =>{
      // req body -->
      //username or email
      //find the user
      // password check 
      // access and refresh token
      // send cookie

    const {email, username, password} = req.body


   if (!username && !email) {
     throw new ApiError (400, "username or password is required")
   }
    const user = await User.findOne({
    $or:[{username}, {email}]
    
   })
    // console.log(user);

    if (!user) {
      throw new ApiError(400, " User does not exists")
      
    }
   const isPasswordValid = await user.isPasswordCorrect(password)
     
    if (!isPasswordValid) {
      throw new ApiError(401, " Invalid user credentials");
    }

 const {accessToken , refreshToken } = await generateAccessAndRefreshToken(user._id)


  const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

  const options = {
    httpOnly : true,
    secure: true
  }
  return res
  .status(200)
  .cookie("accessToken", accessToken , options)
  .cookie("refreshToken", refreshToken , options)
  .json(
    new ApiResponse(
      200,
      {
        user:loggedInUser, accessToken,refreshToken
      },
      "User Logged In Successfully"
    )
  )

})

//log Out User 
 const logoutUser = asyncHandler(async(req,res)=>{
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set:{
        refreshToken:undefined
      }
    },
    {
      new:true
    }
   )
    const options = {
      httpOnly:true,
      secure:true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"))
 
  })

const refreshAccessToken = asyncHandler(async(req,res)=> {
      const incommingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

      if (!incommingRefreshToken) {
        throw new ApiError(401, "unauthorized request")
      }

   try {
     const decodedToken = jwt.verify(incommingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
 
    const user= await User.findById(decodedToken?._id)
 
     if (!user) {
       throw new ApiError(401, "Invalid refresh token");
     }
 
    if (incommingRefreshToken !== user?.refreshToken) {
     throw new ApiError(401, "Refresh token us expired or use")
    }
 
    const options = {
     httpOnly:true,
     secure:true
    }
 
   const {accessToken ,newRefreshToken} = await generateAccessAndRefreshToken(user._id)
 
 
     return res
     .status(200)
     .cookie("accessToken", accessToken, options )
     .cookie("refreshToken",newRefreshToken, options )
     .json(
       new ApiResponse(
         200,
         {
           accessToken ,refreshToken:newRefreshToken
         },
         "Access token refreshed"
       )
     )
 
   } catch (error) {

    throw new ApiError(401, error?.message || "Invlid refresh token")
    
   }

})


export {registerUser , loginUser ,logoutUser, refreshAccessToken }