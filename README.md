# Security Assessment Report: Airdrop Platform
**Repository:** https://github.com/crewspacex/general_blockchain_assessment-2

#### **1. SMART CONTRACT SECURITY ISSUES**

##### 1.1 **Missing Signature Verification Against Signer Address: CRITICAL**
**File:** `components/qatar/Prediction.tsx` (Lines 40-64)  
**URL:** https://github.com/crewspacex/general_blockchain_assessment-2/blob/2c7dc08998ecf27737c8cbc7824ea01b4d4a5dd7/components/qatar/Prediction.tsx#L40-L64

**Vulnerability:**
```tsx
const onSubmit = async () => {
  if (!prediction || !chain || !address || !signature || !collabContract || isLoading || isSubmitted || !deadline) return;
  try {
    setIsLoading(true);
    // PROBLEM: Signature is passed directly to smart contract without verification
    const transactionHash = await collabContract.write.saveStamp(
      ['qatar2022', prediction.ipfs, deadline, signature]  // No signature verification!
    );
```

**Issues:**
- The signature is received as a prop but **never validated** against the current user's address (`address`)
- No cryptographic verification that the signature was signed by the current connected wallet
- An attacker could pass any signature from another user
- The contract might validate it, but the frontend should validate first

**Recommendation:**
```typescript
// Add signature validation before submission
const verifySignature = async () => {
  const message = ethers.utils.solidityKeccak256(
    ['string', 'string', 'uint256'],
    ['qatar2022', prediction.ipfs, deadline]
  );
  const recoveredAddress = ethers.utils.recoverAddress(message, signature);
  if (recoveredAddress.toLowerCase() !== address?.toLowerCase()) {
    throw new Error('Signature does not match the current address');
  }
};
```

##### 1.2 **No Contract Address Validation: HIGH**
**File:** `utils/getContract.ts` (Lines 1-47)  
**URL:** https://github.com/crewspacex/general_blockchain_assessment-2/blob/2c7dc08998ecf27737c8cbc7824ea01b4d4a5dd7/utils/getContract.ts

**Vulnerability:**
```typescript
export const getContract = <TAbi extends Abi | unknown[]>({
  abi,
  address,
  publicClient,
  walletClient,
}: {
  abi: TAbi;
  address: Address;  // No validation that this is a valid contract address
  walletClient?: WalletClient;
  publicClient?: PublicClient;
}) => {
  const c = viemGetContract({
    abi,
    address,  // Directly used without validation
    publicClient: publicClient,
    walletClient: walletClient,
  });
```

**Issues:**
- No validation that `address` is a valid Ethereum address format
- No check if the address actually contains contract code
- Could accept zero address `0x0000000000000000000000000000000000000000`
- Could accept EOA (externally owned accounts) instead of contracts

**Recommendation:**
```typescript
export const getContract = async <TAbi extends Abi | unknown[]>({
  abi,
  address,
  publicClient,
  walletClient,
}: {...}) => {
  // Validate address format
  if (!isAddress(address)) {
    throw new Error('Invalid contract address format');
  }
  
  // Verify it's actually a contract
  if (publicClient) {
    const bytecode = await publicClient.getBytecode({ address });
    if (bytecode === '0x') {
      throw new Error('Address is not a contract');
    }
  }
  
  return viemGetContract({...});
};
```

---

#### **2. AUTHENTICATION & AUTHORIZATION ISSUES**

##### **2.1 No Token Revocation System: HIGH**
**Files:** 
- `backend/utils/jwtToken.js` (Lines 1-37)
- `backend/middlewares/user_actions/auth.js` (Lines 1-41)

**Vulnerability:**
```javascript
// JWT tokens are issued but NEVER revoked
exports.isAuthenticatedUser = asyncErrorHandler(async (req, res, next) => {
    const { token } = req.cookies;
    if (!token) {
        return next(new ErrorHandler("Please Login to Access", 401))
    }
    const decodedData = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decodedData.id);
    // No check if token is blacklisted
    // No check if user logged out
    // No check if user was deleted/disabled
    next();
});
```

**Issues:**
- No token blacklist/invalidation mechanism exists
- Logout doesn't actually invalidate the JWT token
- Users can use old tokens even after logout
- Compromised tokens cannot be revoked
- User deletion doesn't invalidate their tokens

**Recommendation:**
```javascript
// Create a TokenBlacklist model
const TokenBlacklistSchema = new Schema({
  token: String,
  userId: Schema.Types.ObjectId,
  createdAt: { type: Date, default: Date.now, expires: 86400 } // 24 hour TTL
});

// Update auth middleware
exports.isAuthenticatedUser = asyncErrorHandler(async (req, res, next) => {
    const { token } = req.cookies;
    if (!token) {
        return next(new ErrorHandler("Please Login to Access", 401))
    }
    
    // Check if token is blacklisted
    const blacklisted = await TokenBlacklist.findOne({ token });
    if (blacklisted) {
        return next(new ErrorHandler("Token is invalid", 401));
    }
    
    const decodedData = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decodedData.id);
    next();
});

// Logout should blacklist the token
exports.logoutUser = asyncErrorHandler(async (req, res, next) => {
    const { token } = req.cookies;
    if (token) {
        await TokenBlacklist.create({ token });
    }
    res.cookie("token", null, { expires: new Date(Date.now()), httpOnly: true });
    res.status(200).json({ success: true, message: "Logged Out" });
});
```

##### **2.2 No Token Expiration Validation: MEDIUM**
**Files:**
- `backend/models/userModel.js` (Line 60)
- `backend/utils/jwtToken.js` (Lines 5-11)

**Issue:**
```javascript
userSchema.methods.getJWTToken = function () {
    return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRE  // What if JWT_EXPIRE is not set properly?
    });
}
```

**Recommendation:**
- Set a reasonable expiration time (15-30 minutes for access tokens)
- Implement refresh token rotation for long-lived sessions
- Store refresh tokens in database with user association

---

#### **3. INPUT VALIDATION & XSS/INJECTION VULNERABILITIES**

##### **3.1 Missing Input Validation in Profile Update: HIGH**
**File:** `backend/controllers/userController.js` (Lines 162-188)  
**URL:** https://github.com/crewspacex/general_blockchain_assessment-2/blob/2c7dc08998ecf27737c8cbc7824ea01b4d4a5dd7/backend/controllers/userController.js#L162-L188

**Vulnerability:**
```javascript
exports.updateProfile = asyncErrorHandler(async (req, res, next) => {
    const newUserData = {
        name: req.body.name,        // NO VALIDATION - direct assignment
        email: req.body.email,      // NO VALIDATION - direct assignment
    }
    
    if(req.body.avatar !== "") {
        // ...upload logic
    }
    
    // NO INPUT SANITIZATION FOR:
    // - name (could contain XSS)
    // - email (format not validated)
    // - avatar (path traversal risk)
    
    let user = await User.findByIdAndUpdate(req.user.id, newUserData, {
        new: true,
        runValidators: false  // DANGEROUS: Validators are disabled!
    });
});
```

**Issues:**
- No input validation/sanitization middleware applied
- `name` field not validated for XSS injection (`<script>`, `<img onerror=...>`, etc.)
- `email` field not re-validated as proper email format
- `runValidators: false` disables Mongoose schema validation
- No maximum length checks
- No HTML escaping before storage

**Recommendation:**
```javascript
const { body, validationResult } = require('express-validator');

// Add validation middleware to route
router.put('/me/update', 
    isAuthenticatedUser,
    body('name')
        .trim()
        .isLength({ min: 1, max: 100 })
        .withMessage('Name must be between 1-100 characters')
        .escape()  // Escape HTML characters
        .withMessage('Name contains invalid characters'),
    body('email')
        .trim()
        .isEmail()
        .normalizeEmail()
        .withMessage('Invalid email format'),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        next();
    },
    updateProfile
);

// In controller
exports.updateProfile = asyncErrorHandler(async (req, res, next) => {
    const newUserData = {
        name: req.body.name,
        email: req.body.email,
    };
    
    let user = await User.findByIdAndUpdate(req.user.id, newUserData, {
        new: true,
        runValidators: true  // Enable validators
    });
});
```

##### **3.2 Frontend Profile Update Has No Backend Validation: HIGH**
**File:** `hooks/dashboard/arcanaProfile.tsx` (Lines 122-149)  
**URL:** https://github.com/crewspacex/general_blockchain_assessment-2/blob/2c7dc08998ecf27737c8cbc7824ea01b4d4a5dd7/hooks/dashboard/arcanaProfile.tsx#L122-L149

**Vulnerability:**
```tsx
const onSubmit = useCallback(
    async (values: ProfileFormData) => {
        const { twitterHandle, discordHandle, displayName, bio } = values;
        const newProfile: ProfileParams = { bio, showName, twitter, discord };
        Object.assign(newProfile, {
            bio,               // Only client-side maxLength validation (250)
            twitter: twitterHandle,     // No format validation
            discord: discordHandle,     // No format validation
        });
        
        await updateProfile(newProfile);  // Backend has no validation
```

**Issues:**
- Client-side validation only (can be bypassed by manipulating requests)
- No server-side validation of field lengths
- No validation of Twitter/Discord handle formats
- No XSS filtering on `bio` field
- Bio field stored without HTML escaping

**Recommendation:**
```typescript
// Add backend endpoint validation
app.post('/app/profile', isAuthenticatedUser, [
  body('bio')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Bio must be less than 500 characters')
    .escape(),
  body('twitter')
    .optional()
    .trim()
    .matches(/^[a-zA-Z0-9_]{1,15}$/)
    .withMessage('Invalid Twitter handle format'),
  body('discord')
    .optional()
    .trim()
    .matches(/^.{2,32}#[0-9]{4}$/)
    .withMessage('Invalid Discord format'),
], validateInput, updateProfileHandler);
```

##### **3.3 Password Reset - Missing Validation & CSRF Protection: CRITICAL**
**File:** `backend/controllers/userController.js` (Lines 112-148)  
**URL:** https://github.com/crewspacex/general_blockchain_assessment-2/blob/2c7dc08998ecf27737c8cbc7824ea01b4d4a5dd7/backend/controllers/userController.js#L112-L148

**Vulnerability:**
```javascript
exports.resetPassword = asyncErrorHandler(async (req, res, next) => {
    // Create hash token
    const resetPasswordToken = crypto.createHash("sha256").update(req.params.token).digest("hex");

    const user = await User.findOne({ 
        resetPasswordToken,
        resetPasswordExpire: { $gt: Date.now() }
    });

    if(!user) {
        return next(new ErrorHandler("Invalid reset password token", 404));
    }

    user.password = req.body.password;  // NO VALIDATION OF PASSWORD!
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save();  // Password not validated before save
    sendToken(user, 200, res);
});
```

**Issues:**
- **NO PASSWORD VALIDATION** - accepts any password including empty strings
- No check for password strength (min length, complexity)
- No validation middleware called (unlike registration)
- No CSRF token protection on password reset form
- Password reset token doesn't include user ID, could be theoretically brute-forced
- No rate limiting on password reset attempts
- No notification sent when password is reset

**Comparison with Registration:**
```javascript
// Registration HAS validation
exports.validateUserRegister = (req, res, next) => {
    req.check("password")
        .isLength({ min: 6 })
        .withMessage("Password must contain at least 6 characters")
        .matches(/\d/)
        .withMessage("Password must contain a number");
    // ...
}

// But resetPassword DOESN'T validate!
exports.resetPassword = asyncErrorHandler(async (req, res, next) => {
    user.password = req.body.password;  // Directly used without validation
    await user.save();
});
```

**Recommendation:**
```javascript
exports.resetPassword = asyncErrorHandler(async (req, res, next) => {
    // Validate password
    req.check("password", "Password is required").notEmpty();
    req.check("password")
        .isLength({ min: 8 })
        .withMessage("Password must be at least 8 characters")
        .matches(/[A-Z]/)
        .withMessage("Password must contain uppercase")
        .matches(/[a-z]/)
        .withMessage("Password must contain lowercase")
        .matches(/\d/)
        .withMessage("Password must contain a number");
    
    const errors = req.validationErrors();
    if (errors) {
        return res.status(400).json({ error: errors[0].msg });
    }

    // Create hash token
    const resetPasswordToken = crypto.createHash("sha256")
        .update(req.params.token)
        .digest("hex");

    const user = await User.findOne({ 
        resetPasswordToken,
        resetPasswordExpire: { $gt: Date.now() }
    });

    if(!user) {
        return next(new ErrorHandler("Invalid or expired reset token", 404));
    }

    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();
    
    // Send notification email
    await sendEmail({
        email: user.email,
        templateId: process.env.SENDGRID_PASSWORD_RESET_TEMPLATEID,
        data: { name: user.name }
    });
    
    sendToken(user, 200, res);
});
```

##### **3.4 Password Reset Token Generation Could Be Weak: MEDIUM**
**File:** `backend/models/userModel.js` (Lines 64-78)

```javascript
userSchema.methods.getResetPasswordToken = async function () {
    // Generate token - 20 bytes of randomness
    const resetToken = crypto.randomBytes(20).toString("hex");  // Good
    
    // Hash it before storing
    this.resetPasswordToken = crypto.createHash("sha256")
        .update(resetToken)
        .digest("hex");  // Good
    
    // 15 minute expiration
    this.resetPasswordExpire = Date.now() + 15 * 60 * 1000;  // Consider longer
    
    return resetToken;
}
```

**Issue:**
- 15 minutes might be too short for users to check email and reset password
- Token length (20 bytes = 40 hex characters) is acceptable but could be 32 bytes

---

### SUMMARY TABLE

| # | Severity | Category | Issue | File |
|---|----------|----------|-------|------|
| 1 | CRITICAL | Smart Contract | No signature verification against signer address | `components/qatar/Prediction.tsx` |
| 2 | HIGH | Smart Contract | No contract address validation | `utils/getContract.ts` |
| 3 | HIGH | Auth | No token revocation system | `backend/middlewares/user_actions/auth.js` |
| 4 | MEDIUM | Auth | No token expiration enforcement | `backend/utils/jwtToken.js` |
| 5 | HIGH | Input Validation | No validation in profile update endpoint | `backend/controllers/userController.js` |
| 6 | HIGH | Input Validation | Frontend profile update lacks backend validation | `hooks/dashboard/arcanaProfile.tsx` |
| 7 | CRITICAL | Input Validation | Password reset missing validation | `backend/controllers/userController.js` |

---
