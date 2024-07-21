import passport from "passport";
import bcrypt from "bcryptjs";
import User from "../models/user.model.js";
import { GrapgQLLocalStrategy } from "graphql-passport";

// Function to configure passport strategies and serialization
export const configurePassport = async () => {
    // Serialize user to store only the user ID in the session
    passport.serializeUser((user, done) => {
        console.log('Serializing User');
        done(null, user.id);
    });

    // Deserialize user by fetching the full user details using the ID stored in the session
    passport.deserializeUser(async (id, done) => {
        console.log('Deserializing User');
        try {
            const user = await User.findById(id);
            done(null, user);
        } catch (err) {
            done(err);
        }
    });

    // Define the local strategy for authentication using username and password
    passport.use(
        new GrapgQLLocalStrategy(async (username, password, done) => {
            try {
                // Find the user by username
                const user = await User.findOne({ username });
                if (!user) {
                    throw new Error('Invalid username or password');
                }

                // Compare the provided password with the stored hashed password
                const validPassword = await bcrypt.compare(password, user.password);
                if (!validPassword) {
                    throw new Error('Invalid username or password');
                }

                // If authentication is successful, return the user
                return done(null, user);
            } catch (err) {
                // If there's an error during authentication, return the error
                return done(err);
            }
        })
    );
};
