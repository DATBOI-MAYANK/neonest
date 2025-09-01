import User from "@/app/models/User.model";
import connectDB from "@/lib/connectDB";
import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";
import argon2 from "argon2";
export async function POST(req) {
  await connectDB();
  try {
    const body = await req.json();
    const { email, password } = body;

    if (!email || !password) {
      return Response.json({ error: "Please provide all details" }, { status: 422 });
    }

    const userExists = await User.findOne({ email: email.toLowerCase() });
    if (!userExists) {
      return Response.json({ error: "no such user exists! signup instead" }, { status: 422 });
    }

    // const hashPass = await bcryptjs.compare(password , userExists.password);
    // if(!hashPass){
    //   return Response.json(
    //     { error: "wrong password" },
    //     { status: 400 }
    //   );
    // }
    // Checks whether the password was hashed with bcrypt or not (bcrypt hashed password starts with $2)----
    if (userExists.password.startsWith("$2")) {
      const match = await bcryptjs.compare(password, userExists.password);
      if (!match) {
        return Response.json({ error: "wrong password" }, { status: 400 });
      }
      userExists.password = await argon2.hash(password, { type: argon2.argon2id }); // replaces old password with new argon2 hashed password

      await userExists.save();
    } else {
      const match = await argon2.verify(userExists.password, password, { type: argon2.argon2id });
      if (!match) {
        return Response.json({ error: "wrong password" }, { status: 400 });
      }
    }
    const token = jwt.sign(
      {
        id: userExists._id,
        email: userExists.email,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return Response.json(
      {
        success: "login Successful!",
        userExists,
        token,
      },
      { status: 200 }
    );
  } catch (error) {
    console.error(error);
    return Response.json({ error: "Server error" }, { status: 500 });
  }
}
