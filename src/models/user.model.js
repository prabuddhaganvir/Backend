import mongoose , {Schema} from "mongoose"; 
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"

const userSchema = new Schema (
    {
      usename :{
        type:String,
        required:true,
        unique :true,
        lowercase:true,
        trim:true,
        index:true
      },
      email :{
        type:String,
        required:true,
        unique :true,
        lowercase:true,
        trim:true,
  
      },
      email :{
        type:String,
        required:true,
        unique :true,
        trim:true,
        index:true
  
      },
      fullName:{
        type:String,
        required:true,
        trim:true,
        index:true

      },
      avatar:{
        type:String, //cloudinary url
        required:true,
  
      },
      coverImage :{
        type:String
      },
      watchHistory :[
        {
            type:Schema.Types.ObjectId,
            ref:"Video"
        }
      ],
      password:{
        type:String,
        required:[true, "password is required"]
      },
      refreshTokens:{
        type:String
      }


    },{

        timestamp: true
    }

)


userSchema.pre("save", async function (next) {

    if (!this.isModified("password")) return next();
    this.password = bcrypt.hash(this.password, 10)
    next()
})

userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password)
}

userSchema.methods.generateAccessToken = function (params) {
  return  jwt.sign(
        {
            _id:this._id,
            email:this.email,
            username:this.username,
            fullName:this.fullName

        },
        process.env.ACCESS_TOKEN_SECRET,
        {
           expiresIn:process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}
userSchema.methods.generateRefreshToken = function (params) {
     return jwt.sign(
       {
         _id: this._id,
       },
       process.env.REFRESH_TOKEN_SECRET,
       {
         expiresIn: process.env.REFRESH_TOKEN_SECRET,
       }
    );
}


export const USer = mongoose.model("User", userSchema)