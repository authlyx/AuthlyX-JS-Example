# AuthlyX JavaScript SDK

This is a JavaScript authentication SDK for Node.js applications that want simple integration with the AuthlyX API.

This folder is primarily for SDK users. The script here is only a reference example to help you integrate faster.

## Requirements

- Node.js 18+ (for built-in `fetch`)

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
if (!AuthlyXApp.response.success) {
  console.log(AuthlyXApp.response.message);
  return;
}
```

## Optional Parameters

```js
const { AuthlyX } = require("./AuthlyX");

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

## Init

```js
await AuthlyXApp.Init();

if (AuthlyXApp.response.success) {
  console.log("Init success");
} else {
  console.log(AuthlyXApp.response.message);
}
```

## Login (Unified)

`Login(...)` is a single entry point that supports:

- username/password login
- license login
- device login

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

### License Login

```js
await AuthlyXApp.Login("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX");

if (AuthlyXApp.response.success) {
  console.log("License login success");
} else {
  console.log(AuthlyXApp.response.message);
}
```

### Device Login (Motherboard)

```js
await AuthlyXApp.Login("YOUR_MOTHERBOARD_ID", null, "motherboard");

if (AuthlyXApp.response.success) {
  console.log("Device login success");
} else {
  console.log(AuthlyXApp.response.message);
}
```

### Device Login (Processor)

```js
await AuthlyXApp.Login("YOUR_PROCESSOR_ID", null, "processor");

if (AuthlyXApp.response.success) {
  console.log("Device login success");
} else {
  console.log(AuthlyXApp.response.message);
}
```

## Register

```js
await AuthlyXApp.Register("new_user", "password", "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX", "user@example.com");

if (AuthlyXApp.response.success) {
  console.log("Registered successfully");
} else {
  console.log(AuthlyXApp.response.message);
}
```

## Extend Time

```js
await AuthlyXApp.ExtendTime("username", "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX");

if (AuthlyXApp.response.success) {
  console.log("Extended successfully");
  console.log("New expiry:", AuthlyXApp.userData.expiryDate);
} else {
  console.log(AuthlyXApp.response.message);
}
```

## Change Password

```js
await AuthlyXApp.ChangePassword("old_password", "new_password");

if (AuthlyXApp.response.success) {
  console.log("Password changed successfully");
} else {
  console.log(AuthlyXApp.response.message);
}
```

## Variables

```js
await AuthlyXApp.SetVariable("theme", "dark");
console.log(AuthlyXApp.response.message);

const value = await AuthlyXApp.GetVariable("theme");
if (AuthlyXApp.response.success) {
  console.log("theme =", value);
} else {
  console.log(AuthlyXApp.response.message);
}
```

## Chats

```js
await AuthlyXApp.SendChat("Hello world", "MAIN");
console.log(AuthlyXApp.response.message);

await AuthlyXApp.GetChats("MAIN");
if (AuthlyXApp.response.success) {
  for (const msg of AuthlyXApp.chatMessages.messages) {
    console.log(`[${msg.createdAt}] ${msg.username}: ${msg.message}`);
  }
} else {
  console.log(AuthlyXApp.response.message);
}
```

## Validate Session

```js
await AuthlyXApp.ValidateSession();

if (AuthlyXApp.response.success) {
  console.log("Session is valid");
} else {
  console.log(AuthlyXApp.response.message);
}
```

## User Data

After a successful login, the SDK populates `AuthlyXApp.userData`:

- `username`
- `email`
- `licenseKey`
- `subscription`
- `subscriptionLevel`
- `expiryDate`
- `daysLeft`
- `lastLogin`
- `hwid` (this is the Windows SID where available)
- `ipAddress`
- `registeredAt`

