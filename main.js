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
  const api = process.env.AUTHLYX_API || "http://localhost:4000/api/v2";
  const AuthlyXApp = new AuthlyX(
    "12345678",
    "HI",
    "1.3",
    "qIBFoBJWQH4jaOZr6Sf8BJZyEVnT0LiN4QfRxJGn",
    true,
    api
  );

  await AuthlyXApp.refreshPublicIpCache();

  await AuthlyXApp.Init();
  showResult("Init", AuthlyXApp);

  await AuthlyXApp.Login("12", "1");
  showResult("Login", AuthlyXApp);
  showUser(AuthlyXApp);

  await AuthlyXApp.SetVariable("hehe", "me");
  showResult("Set Variable", AuthlyXApp);

  const val = await AuthlyXApp.GetVariable("hehe");
  showResult("Get Variable", AuthlyXApp);
  if (AuthlyXApp.response.success) console.log("Value:", val);

  await AuthlyXApp.Login("X6VXY-5VIVE-PT6SY-O8FNX-AEDJL");
  showResult("License Login", AuthlyXApp);
  showUser(AuthlyXApp);

  await AuthlyXApp.Login("PDPCF001X4YJ2Q", null, "motherboard");
  showResult("Device Login (motherboard)", AuthlyXApp);
  showUser(AuthlyXApp);

  await AuthlyXApp.ValidateSession();
  showResult("Validate Session", AuthlyXApp);
}

main().catch((e) => {
  console.error("Example error:", e && e.message ? e.message : String(e));
});

