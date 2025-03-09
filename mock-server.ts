import express from 'express';
import session from 'express-session';
import bodyParser from 'body-parser';
import { generateKeyPairSync, KeyObject } from 'crypto';
import crypto from 'crypto';
import jwt, { JwtPayload } from 'jsonwebtoken';

/***************************************************************************
 * 1. Generate ephemeral RSA key pair (RS256)
 ***************************************************************************/
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

function generateJWKFromPublicKey(pubKey: KeyObject) {
  const keyData = pubKey.export({ format: 'jwk' });
  return {
    keys: [
      {
        kty: 'RSA',
        alg: 'RS256',
        use: 'sig',
        kid: 'mock-kid-' + Date.now(),
        n: keyData.n,
        e: keyData.e
      }
    ]
  };
}

const jwkSet = generateJWKFromPublicKey(publicKey);

/***************************************************************************
 * 2. In-memory data stores
 ***************************************************************************/
interface User {
  id: number;
  email: string;
  password: string;
  name: string;
}

interface Client {
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
}

interface AuthorizationCode {
  code: string;
  userId: number;
  clientId: string;
  redirectUri: string;
  scope: string;
  nonce?: string;
  expiresAt: number;
}

interface RefreshToken {
  token: string;
  userId: number;
  expiresAt: number;
}

const memory = {
  users: [
    { id: 1, email: 'alice@example.com', password: 'password', name: 'Alice Doe' }
  ] as User[],

  clients: [
    {
      clientId: "77185425430.apps.googleusercontent.com",
      clientSecret: 'test-secret',
      redirectUris: ['https://your-chromium-callback-url/callback']
    }
  ] as Client[],

  authorizationCodes: new Map<string, AuthorizationCode>(),
  refreshTokens: new Map<string, RefreshToken>()
};

/***************************************************************************
 * 3. App & Middleware Setup
 ***************************************************************************/
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: 'replace-with-random-string',
  resave: false,
  saveUninitialized: false
}));

// Add CORS headers to allow cross-origin requests
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

/***************************************************************************
 * 4. ListAccounts Endpoint
 *    Simulates Google's ListAccounts endpoint.
 ***************************************************************************/
app.post('/ListAccounts', (req, res) => {
  // Simulate Google's ListAccounts response
  const response = {
    accounts: memory.users.map(user => ({
      id: user.id,
      email: user.email,
      isSignedIn: true,
      isPrimary: true,
      isDefault: true,
      isManaged: false,
      isChild: false,
      isUnderAdvancedProtection: false,
      pictureUrl: 'https://example.com/profile.jpg'
    })),
    primaryAccountId: memory.users[0].id
  };

  // Set headers to match Google's response
  res.set('Content-Type', 'application/json; charset=utf-8');
  res.set('Access-Control-Allow-Origin', 'https://www.google.com');
  res.set('Access-Control-Allow-Credentials', 'true');
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', 'Mon, 01 Jan 1990 00:00:00 GMT');
  res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.set('Accept-CH', 'Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Model, Sec-CH-UA-WoW64, Sec-CH-UA-Form-Factors, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version');
  res.set('Cross-Origin-Opener-Policy', 'same-origin');
  res.set('Content-Security-Policy', "script-src 'report-sample' 'nonce-wYMXXcmyzV3wapKwMGp94A' 'unsafe-inline';object-src 'none';base-uri 'self';report-uri /_/IdentityListAccountsHttp/cspreport;worker-src 'self'");
  res.set('Permissions-Policy', 'ch-ua-arch=*, ch-ua-bitness=*, ch-ua-full-version=*, ch-ua-full-version-list=*, ch-ua-model=*, ch-ua-wow64=*, ch-ua-form-factors=*, ch-ua-platform=*, ch-ua-platform-version=*');
  res.set('Reporting-Endpoints', 'default="/_/IdentityListAccountsHttp/web-reports?context=eJzjEtHikmII0pBiOHxtB5Meyy0mIyAW4ub49WvDPjaBB2s2hSnpJuUXxmempOaVZJZU5mQWlyQmJ-eX5pUUF6cWlaUWxRsZGJkaGBsY6RlYxBcYAABxIBw0"');
  res.set('Server', 'ESF');
  res.set('X-XSS-Protection', '0');

  // Send the response
  res.status(200).json(response);
});

app.get('/oauth2/v1/userinfo', (req, res) => {
  const userInfo = {
    id: "1234567890",
    email: "alice@example.com",
    verified_email: true,
    name: "Alice Doe",
    given_name: "Alice",
    family_name: "Doe",
    picture: "https://example.com/profile.jpg",
    locale: "en"
  };

  res.set({
    'Cache-Control': 'no-cache, no-store, max-age=0, must-revalidate',
    'Pragma': 'no-cache',
    'Expires': 'Mon, 01 Jan 1990 00:00:00 GMT',
    'Content-Type': 'application/json; charset=UTF-8',
    'Vary': 'Origin, X-Origin, Referer'
  });
  
  res.status(200).json(userInfo);
});

/***************************************************************************
 * 5. Basic UI for Login
 *    Serves a simple HTML form at GET /login.
 ***************************************************************************/
app.get('/login', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Login</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; }
          form { max-width: 300px; margin: auto; }
          label, input { display: block; width: 100%; margin-bottom: 10px; }
          input[type="submit"] { margin-top: 20px; }
        </style>
      </head>
      <body>
        <h1>Login</h1>
        <form method="post" action="/login">
          <label for="email">Email:</label>
          <input type="email" id="email" name="email" required />
          <label for="password">Password:</label>
          <input type="password" id="password" name="password" required />
          <input type="hidden" name="nonce" value="sample-nonce" />
          <input type="submit" value="Login" />
        </form>
      </body>
    </html>
  `);
});

/***************************************************************************
 * 6. Adapted Login Endpoint for Chromium Native Sign‑in
 *    Validates credentials, generates an authorization code (with empty redirectUri),
 *    and sends the required header with no response body.
 ***************************************************************************/
app.post('/login', (req, res) => {
  const { email, password, nonce } = req.body;
  const user = memory.users.find(u => u.email === email && u.password === password);
  if (!user) {
    res.status(401).end();
    return;
  }

  // Generate an authorization code.
  const code = crypto.randomBytes(16).toString('hex');
  // Store the code with an empty redirectUri (native Chromium flow)
  memory.authorizationCodes.set(code, {
    code,
    userId: user.id,
    clientId: '77185425430.apps.googleusercontent.com,',
    redirectUri: '',
    scope: 'openid email profile',
    nonce: nonce,
    expiresAt: Date.now() + 5 * 60 * 1000 // Code valid for 5 minutes
  });

  // Build the Dice header exactly as Chromium expects.
  const diceHeader = `action=SIGNIN,authuser=0,authorization_code=${code},email=${encodeURIComponent(user.email)},id=${user.id},eligible_for_token_binding=false`;
  
  // Log the header for debugging
  console.log('DICE Header:', diceHeader);

  // Set the custom header for Chromium.
  res.set('X-Chrome-ID-Consistency-Response', diceHeader);

  // Do not send any response body – only the header is sent.
  res.status(200).end();
});

/***************************************************************************
 * 7. Token Endpoint
 *    Accepts the authorization code and returns tokens.
 ***************************************************************************/
app.post('/token', (req, res) => {
  const { grant_type, code, client_id, client_secret } = req.body;

    const expiresIn = 3600; // 1 hour in seconds
    const now = Math.floor(Date.now() / 1000);
    
    // Create access token.
    const accessToken = jwt.sign({
      sub: "1",
      email: "alice@example.com",
      aud: client_id,
      iss: 'https://your-domain.com',
      iat: now,
      exp: now + expiresIn
    }, privateKey, { algorithm: 'RS256' });
    
    // Create ID token formatted for Chrome.
    const idToken = jwt.sign({
      iss: 'https://your-domain.com',
      sub: "1",
      aud: client_id,
      azp: client_id,
      iat: now,
      exp: now + expiresIn,
      email: "alice@example.com",
      email_verified: true,
      name: "Alice Doe"
    }, privateKey, { algorithm: 'RS256' });
    
    // Generate refresh token.
    const refreshToken = crypto.randomBytes(32).toString('hex');
    memory.refreshTokens.set(refreshToken, {
      token: refreshToken,
      userId: 1,
      expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000
    });

    const scopes = req.body.scope;

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      refresh_token: refreshToken,
      scope: scopes.toString(),
      expires_in: expiresIn,
      id_token: idToken
    });
});

app.use(express.static('public'));

app.post('/v1/accountcapabilities:batchGet', (req, res) => {
  // Optionally, you can inspect the request body (req.body) if needed.
  const response = {
    "accountCapabilities": [
      { "name": "accountcapabilities/haytqlldmfya", "booleanValue": true },
      { "name": "accountcapabilities/gi2tklldmfya", "booleanValue": true },
      { "name": "accountcapabilities/gu2dqlldmfya", "booleanValue": true },
      { "name": "accountcapabilities/guzdslldmfya", "booleanValue": true },
      { "name": "accountcapabilities/ge2dinbnmnqxa", "booleanValue": true },
      { "name": "accountcapabilities/gu4dmlldmfya", "booleanValue": true },
      { "name": "accountcapabilities/geydgnznmnqxa", "booleanValue": true },
      { "name": "accountcapabilities/ge2tkmznmnqxa", "booleanValue": true },
      { "name": "accountcapabilities/geztenjnmnqxa", "booleanValue": true },
      { "name": "accountcapabilities/geytcnbnmnqxa", "booleanValue": true },
      { "name": "accountcapabilities/gezdcnbnmnqxa", "booleanValue": true },
      { "name": "accountcapabilities/g42tslldmfya", "booleanValue": true },
      { "name": "accountcapabilities/he4tolldmfya", "booleanValue": true },
      { "name": "accountcapabilities/g44tilldmfya", "booleanValue": true },
      { "name": "accountcapabilities/guydolldmfya", "booleanValue": true },
      { "name": "accountcapabilities/gezdsmbnmnqxa", "booleanValue": true },
      { "name": "accountcapabilities/ge2tknznmnqxa", "booleanValue": true },
      { "name": "accountcapabilities/ge2tkobnmnqxa", "booleanValue": true },
      { "name": "accountcapabilities/ge3dgobnmnqxa", "booleanValue": true }
    ]
  };

  res.status(200).json(response);
});


/***************************************************************************
 * 8. Start Server
 ***************************************************************************/
app.listen(5000, () => {
  console.log('OIDC server running at http://localhost:5000');
});