import bcrypt from 'bcryptjs';
import User from "../models/user.model.js";

const userResolver = {
    Mutation: {
        /**
         * Signs up a new user.
         * @param {object} _ - Unused parameter.
         * @param {object} input - The input object containing user details.
         * @param {string} input.username - The username of the user.
         * @param {string} input.name - The name of the user.
         * @param {string} input.password - The password of the user.
         * @param {string} input.gender - The gender of the user.
         * @param {object} context - The context object.
         * @returns {object} The newly created user.
         */
        signUp: async (_, { input }, context) => {
            try {
                const { username, name, password, gender } = input;
                if (!username || !name || !password || !gender) {
                    throw new Error('All fields are required');
                }

                const existingUser = await User.findOne({ username });
                if (existingUser) {
                    throw new Error('User already exists');
                }

                const salt = await bcrypt.genSalt(10);
                const hashedPassword = await bcrypt.hash(password, salt);

                // https://avatar-placeholder.iran.liara.run/
                const boyProfilePic = `https://avatar.iran.liara.run/public/boy?username=${username}`;
                const girlProfilePic = `https://avatar.iran.liara.run/public/girl?username=${username}`;

                const newUser = new User({
                    username,
                    name,
                    password: hashedPassword,
                    gender,
                    profilePicture: gender === 'male' ? boyProfilePic : girlProfilePic,
                });

                await newUser.save();
                await context.login(newUser);

                return newUser;
            } catch (err) {
                console.error('Error in SignUp:', err);
                throw new Error(err.message || 'Internal Server Error');
            }
        },

        /**
         * Logs in a user.
         * @param {object} _ - Unused parameter.
         * @param {object} input - The input object containing login details.
         * @param {string} input.username - The username of the user.
         * @param {string} input.password - The password of the user.
         * @param {object} context - The context object.
         * @returns {object} The logged-in user.
         */
        login: async (_, { input }, context) => {
            try {
                const { username, password } = input;
                if (!username || !password) {
                    throw new Error("All fields are required");
                }
                const { user } = await context.authenticate('graphql-local', { username, password });

                await context.login(user);

                return user;
            } catch (err) {
                console.error('Error in Login:', err);
                throw new Error(err.message || 'Internal Server Error');
            }
        },

        /**
         * Logs out a user.
         * @param {object} _ - Unused parameter.
         * @param {object} __ - Unused parameter.
         * @param {object} context - The context object.
         * @returns {object} A message indicating the user has logged out.
         */
        logout: async (_, __, context) => {
            try {
                await context.logout();
                context.req.session.destroy((err) => {
                    if (err) throw err;
                });
                context.res.clearCookie('connect.sid');

                return { message: 'Logged Out Successfully' };
            } catch (err) {
                console.error('Error in Logout:', err);
                throw new Error(err.message || 'Internal Server Error');
            }
        },
    },
    Query: {
        /**
         * Gets the authenticated user.
         * @param {object} _ - Unused parameter.
         * @param {object} __ - Unused parameter.
         * @param {object} context - The context object.
         * @returns {object} The authenticated user.
         */
        authUser: async (_, __, context) => {
            try {
                const user = await context.getUser();
                return user;
            } catch (err) {
                console.error('Error in authUser:', err);
                throw new Error(err.message || 'Internal Server Error');
            }
        },

        /**
         * Gets a user by ID.
         * @param {object} _ - Unused parameter.
         * @param {string} userId - The ID of the user.
         * @returns {object} The user with the specified ID.
         */
        user: async (_, { userId }) => {
            try {
                const user = await User.findById(userId);
                return user;
            } catch (err) {
                console.error('Error in user query:', err);
                throw new Error(err.message || 'Error getting user');
            }
        },
    },
    // TODO: ADD USER/TRANSACTION RELATION
};

export default userResolver;
