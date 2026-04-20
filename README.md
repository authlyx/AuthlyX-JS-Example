# AuthlyX JavaScript SDK

This is a JavaScript authentication SDK for Node.js applications that want simple integration with the AuthlyX API.

This folder includes the SDK in `AuthlyX.js` and a runnable example in `main.js`.

## Requirements

- Node.js `18+`

## Install

Copy `AuthlyX.js` into your project and import it:

```js
const { AuthlyX } = require("./AuthlyX");
```

## Quick Start

```js
const { AuthlyX } = require("./AuthlyX");

const AuthlyXApp = new AuthlyX(
  "12345678",
  "MYAPP",
  "1.0.0",
  "your-secret"
);

await AuthlyXApp.Init();
```

## Optional Parameters

```js
const AuthlyXApp = new AuthlyX(
  "12345678",
  "MYAPP",
  "1.0.0",
  "your-secret",
  false,
  "https://example.com/api/v2"
);
```

### Available options

- `debug`
  - Default: `true`
  - Set `false` to disable SDK logs

- `api`
  - Default: `https://authly.cc/api/v2`
  - Use this for your custom domain

## Available Methods

- `Init()`
- `Login(identifier, password = null, deviceType = null)`
- `Register(username, password, licenseKey, email = "")`
- `ChangePassword(oldPassword, newPassword)`
- `ExtendTime(username, licenseKey)`
- `GetVariable(key)`
- `SetVariable(key, value)`
- `Log(message)`
- `GetChats(channelName, limit = 100, cursor = null)`
- `SendChat(message, channelName = null)`
- `ValidateSession()`

All methods return a Promise.

## Authentication Example

```js
// Username + password
await AuthlyXApp.Login("username", "password");

// License key only
await AuthlyXApp.Login("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX");

// Device login
await AuthlyXApp.Login("YOUR_MOTHERBOARD_ID", null, "motherboard");
```

## Username Login Example

```js
await AuthlyXApp.Login("username", "password");

if (AuthlyXApp.response.success) {
  console.log("Login success");
  console.log(AuthlyXApp.userData.username);
  console.log(AuthlyXApp.userData.subscriptionLevel);
} else {
  console.log(AuthlyXApp.response.message);
}
```

## Variable Example

```js
await AuthlyXApp.SetVariable("theme", "dark");

const value = await AuthlyXApp.GetVariable("theme");
console.log(value);
```

## Logging

By default, SDK logging is enabled.

Logs are written to:

`C:\ProgramData\AuthlyX\{AppName}\YYYY_MM_DD.log`

To disable logs:

```js
const AuthlyXApp = new AuthlyX(
  "12345678",
  "MYAPP",
  "1.0.0",
  "your-secret",
  false,
  "https://authly.cc/api/v2"
);
```

Sensitive values such as passwords, secrets, session IDs, request IDs, nonces, license keys, and hashes are masked automatically.

## Example Project

The runnable example in `main.js` uses the public test app by default for `Init()`.

If you want to run the authenticated example too, set:

- `AUTHLYX_USERNAME`
- `AUTHLYX_PASSWORD`

Then run:

```powershell
node main.js
```
