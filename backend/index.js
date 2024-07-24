import express from 'express';
import http from 'http';
import cors from 'cors';
import dotenv from 'dotenv';

// Authentication Imports
import passport from 'passport';
import session from 'express-session';
import connectMongo from 'connect-mongodb-session';
import { buildContext } from "graphql-passport";
import { configurePassport } from './passport/passport.config.js';

// Apollo imports
import { ApolloServer } from '@apollo/server';
import { startStandaloneServer } from '@apollo/server/standalone';
import { expressMiddleware } from '@apollo/server/express4';
import { ApolloServerPluginDrainHttpServer } from '@apollo/server/plugin/drainHttpServer';

// Schema imports
import mergedResolvers from './resolvers/index.js';
import mergedTypeDefs from './typeDefs/index.js';

// DB import
import { connectDB } from './db/connectDB.js';


const app = express();
dotenv.config();
configurePassport();

// Our httpServer handles incoming requests to our Express app.
// Below, we tell Apollo Server to "drain" this httpServer,
// enabling our servers to shut down gracefully.
const httpServer = http.createServer(app);

const MongoDBStore = connectMongo(session);

const store = new MongoDBStore({
    uri: process.env.MONGO_URI,
    collection: 'sessions',
});

store.on('error', (err) => {
    console.log(err);
});

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false, //This option specifies whether to save the session to the store on every request;
        saveUninitialized: false, //option specifies whether to save unitialized sessions;
        cookie: {
            maxAge: 1000 * 60 * 60 * 24 * 7,
            httpOnly: true, //this option prevents the Cross-site scriptiing (XSS) attacks
        },
        store: store
    })
);

app.use(passport.initialize());
app.use(passport.session());

const server = new ApolloServer({
    typeDefs: mergedTypeDefs,
    resolvers: mergedResolvers,
    plugins: [ApolloServerPluginDrainHttpServer({ httpServer })],
});

// Ensure we wait for our server to start
await server.start();

// Set up our Express middleware to handle CORS, body parsing,
// and our expressMiddleware function.
app.use(
    '/graphql',
    cors({
        origin: 'http://localhost:5001',
        credentials: true,
    }),
    express.json(),
    // expressMiddleware accepts the same arguments:
    // an Apollo Server instance and optional configuration options
    expressMiddleware(server, {
        context: async ({ req, res }) => buildContext({ req, res }),
    }),
);

// Modified server startup
await new Promise((resolve) => httpServer.listen({ port: 4000 }, resolve));

// DB Connection
await connectDB();

console.log(`🚀 Server ready at http://localhost:4000/graphql`);
