const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const DailyUserCount = require('./DailyUserCount');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  email: { 
      type: String, 
      required: true, 
      unique: true, 
      trim: true, 
      lowercase: true, 
      match: [/\S+@\S+\.\S+/, 'Please use a valid email address']
  },
  phoneNumber: { 
      type: String, 
      required: true, 
      trim: true, 
      match: [/^[0-9+()\-\s]{7,25}$/, 'Please provide a valid phone number']
  },
  firstName: { type: String, trim: true, default: null },
  middleInitial: { type: String, trim: true, default: null },
  lastName: { type: String, trim: true, default: null },
  suffix: { type: String, trim: true, default: null },
  birthdate: { type: Date, default: null },
  sex: { 
      type: String, 
      enum: ['Male', 'Female', 'Other'], 
      default: null 
  },
   nationality: { type: String, trim: true, default: null },
  isActive: { type: Boolean, default: true },
  password: { type: String, required: true, minlength: 8 },
}, { timestamps: true });

userSchema.pre('save', async function (next) {
  try {
      if (this.isModified('password')) {
          const isAlreadyHashed = this.password.startsWith('$2b$');
          if (!isAlreadyHashed) {
              const salt = await bcrypt.genSalt(10);
              this.password = await bcrypt.hash(this.password, salt);
          }
      }
      next();
  } catch (error) {
      next(error);
  }
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.statics.findByUsernameOrEmail = async function (identifier) {
  return await this.findOne({
      $or: [{ username: identifier }, { email: identifier }]
  });
};

userSchema.post('save', async function () {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const dailyUser = await DailyUserCount.findOne({ date: today });

  if (dailyUser) {
    dailyUser.count += 1;
    await dailyUser.save();
  } else {
    await DailyUserCount.create({ date: today, count: 1 });
  }

  console.log('User registered and daily user count updated');
});

const User = mongoose.model('User', userSchema);

module.exports = User;
