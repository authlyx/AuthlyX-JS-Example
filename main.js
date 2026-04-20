const { AuthlyX } = require("./AuthlyX");

function showResult(title, sdk) {
  const r = sdk.response;
  const ok = r.success ? "SUCCESS" : "FAILED";
  console.log("");
  console.log(`${title}: ${ok}`);
  console.log(`Message: ${r.message}`);
  if (r.code) console.log(`Code: ${r.code}`);
  if (r.statusCode) console.log(`Status: ${r.statusCode}`);
}

function showUser(sdk) {
  const u = sdk.userData;
  console.log("");
  console.log("USER PROFILE");
  console.log("==============================================");
  console.log(`Username: ${u.username || "N/A"}`);
  console.log(`Email: ${u.email || "N/A"}`);
  console.log(`License Key: ${u.licenseKey || "N/A"}`);
  console.log(`Subscription: ${u.subscription || "N/A"}`);
  console.log(`Subscription Level: ${u.subscriptionLevel || "N/A"}`);
  console.log(`Expiry Date: ${u.expiryDate || "N/A"}`);
  console.log(`Days Left: ${u.daysLeft || 0}`);
  console.log(`Last Login: ${u.lastLogin || "N/A"}`);
  console.log(`Registered At: ${u.registeredAt || "N/A"}`);
  console.log(`HWID/SID: ${u.hwid || "N/A"}`);
  console.log(`IP Address: ${u.ipAddress || "N/A"}`);
  console.log("==============================================");
}

async function main() {
  const api = process.env.AUTHLYX_API || "https://authly.cc/api/v2";
  const ownerId = process.env.AUTHLYX_OWNER_ID || "b49d11af8c42";
  const appName = process.env.AUTHLYX_APP_NAME || "TEST";
  const version = process.env.AUTHLYX_VERSION || "1.3";
  const secret = process.env.AUTHLYX_SECRET || "1L0edLKqHlFv0AL3NIQ7uPpikN2ECr7aZSHrNWMo";
  const username = process.env.AUTHLYX_USERNAME || "";
  const password = process.env.AUTHLYX_PASSWORD || "";
  const AuthlyXApp = new AuthlyX(
    ownerId,
    appName,
    version,
    secret,
    true,
    api
  );

  await AuthlyXApp.refreshPublicIpCache();

  await AuthlyXApp.Init();
  showResult("Init", AuthlyXApp);
  if (!AuthlyXApp.response.success) return;

  if (username && password) {
    await AuthlyXApp.Login(username, password);
    showResult("Login", AuthlyXApp);
    if (AuthlyXApp.response.success) {
      showUser(AuthlyXApp);

      await AuthlyXApp.SetVariable("theme", "dark");
      showResult("Set Variable", AuthlyXApp);

      const val = await AuthlyXApp.GetVariable("theme");
      showResult("Get Variable", AuthlyXApp);
      if (AuthlyXApp.response.success) console.log("Value:", val);

      await AuthlyXApp.ValidateSession();
      showResult("Validate Session", AuthlyXApp);
    }
    return;
  }

  console.log("");
  console.log("Init completed.");
  console.log("Set AUTHLYX_USERNAME and AUTHLYX_PASSWORD if you want to run the authenticated examples.");
}

main().catch((e) => {
  console.error("Example error:", e && e.message ? e.message : String(e));
});
