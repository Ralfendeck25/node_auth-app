import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as FacebookStrategy } from 'passport-facebook';
import { Strategy as GitHubStrategy } from 'passport-github2';
import User from '../models/User.js';

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ email: profile.emails[0].value });
    
    if (!user) {
      // Create new user
      user = await User.create({
        name: profile.displayName,
        email: profile.emails[0].value,
        password: 'google-auth', // Will be changed if user sets password
        active: true,
        socialAccounts: [{
          provider: 'google',
          providerId: profile.id
        }]
      });
    } else {
      // Check if Google account is already linked
      const isLinked = user.socialAccounts.some(acc => 
        acc.provider === 'google' && acc.providerId === profile.id
      );
      
      if (!isLinked) {
        user.socialAccounts.push({
          provider: 'google',
          providerId: profile.id
        });
        await user.save();
      }
    }
    
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

// Similar strategies for Facebook and GitHub...

export default passport;
