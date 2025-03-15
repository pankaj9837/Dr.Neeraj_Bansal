/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import express from "express";
import { decryptRequest, encryptResponse, FlowEndpointException } from "./encryption.js";
import { getNextScreen } from "./flow.js";
import crypto from "crypto";

const app = express();

app.use(
  express.json({
    // store the raw request body to use it for signature verification
    verify: (req, res, buf, encoding) => {
      req.rawBody = buf?.toString(encoding || "utf8");
    },
  }),
);

const { PORT = "3000" } = process.env;
const PASSPHRASE = "password"
const APP_SECRET = "62528c1b0adc2320d8b6e27b0254ede0"
const PRIVATE_KEY = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFJDBWBgkqhkiG9w0BBQ0wSTAxBgkqhkiG9w0BBQwwJAQQNxRsdQY3ZxCRhhRg
YPsxcgICCAAwDAYIKoZIhvcNAgkFADAUBggqhkiG9w0DBwQIRXIfeYDwfFUEggTI
/OKx+yH0WFgHErS+htFIJ+hsagBtU+sJefuOlCFqju3/oVoRoK26lhFW3/7O4hfU
nVM+CGiHEGmD/UHAkzw3EcB3q6MUhzdXBhZOI6UNZBcrHlCDNX+IbDK+gyBVCIN1
NYjSvUa/Zu6Tn/iIzj9GCriE+/T4ZIrZ/NpqERwkzGP4ptHrX0nOAqsIPfzqCkdy
xyf7E5wNssZJV7ZSPuwLzNQZH4RQvYgxDXK5dR0Hzyw2IAaB3V3RAhaoM8eU7o24
i3Wl9FuXhDuyKfbTJInPEUCsxBzRypY8Tk+3OMQD4rkkrFjo6GarRauizgn4/UND
n12GOFBaPXmgPkTMuBm/016GANHF5l6e5DPVrWvKrHgbozGarYhLUi5CU6ll47kc
ZDWGP0GGiQWLotZJBg5hVKB0Y5QVrl1lo0BquW794ymzN3GQPw5WiaZuash6fzSq
frZQL2/8y/S7faV7u80dlWaMHlG95XuHqibGP04p7Sjqn76ByjDHZSBtdnh2Qqjc
UAOVeYxKwZfMg8vd28TlzUovKoAzUFh/tNdbbsf5x7/VyfG5HWAmWrb8qEhPG712
jl43st6xfR7x82Kn0x9FylZZ5tisuxAWA+WcDkva8mcb6HTpd/kvi6HOf78mhskK
pj8B8LHfAQTfSvvsvJYiyZ9ZexQBDmLIEUqI9fS9Z0fi7KWEKjTBj5vKn/+e7YjO
h6Plr6UfDavParPhHCmFbX2TaX2/CPVCJDJTol3lmh8Wc3DftHn0WmD0h0/KADze
d49rRxoqATtWyz5O2pRL9VZURu+2PEzsZzR/VOBAtiHKla9bNyqSfsLLmPRsPht6
huqQVUYSOFDilCseOssG8gosWjpdFHMkQDWd/8g7FNoDVx5kTSTdD0g0TWwWGA6l
/5FE3W4KNhmPIhOtE9axhfcD+ayrK1F8PwEY4jYrrbgEpG3lmA0uZFjDdgoRSLiQ
0qZrRTiro3U5KKPQyWqlmsjJ6DiwBt1KE41hchZwXAjsUwfBp48Gi95T+8fTlpUN
R1RXVkNOQJxnlb1x/XEvsVMe/gwfcBKZHCeY8PTondoEvddwkUBLNEusr4DkoOFo
etj61LE4yMrrFpMhLb/dQLmfZd1JiV4e4GmSnCuPt3jiV6M8QL+zocyij+k3xB1y
LrCLDxmQ+i8bteQ4TsZsJCyU7fV+DLvdKRy4D4K07IbRPtCWN+gZ31G+GfLKaC93
Zj50Lt1k+HBXw5o69EvdyNrZqMHHpejXH9+tWa2tz09jt2vvCLGPzT9CHn5CLb6y
CW/+J4tLU0YEwp49FSoTXe69jVlAc4+cQlyuXtSne9sehKQSbYsnYqPBIGdCz9+6
yIVN/Q3Wm+AChCB9xjLU4dQDt/zBngxYAvlZx6mYGrsqzOBvFnnbtRUXL1oN399M
TXxvjc/QoxzVgy841G89LyW2U+Ak/GtbEXmKEySZctvbJOdJHIEfA23WVS3HlX+C
/9R68G33DjHe/ThbjRxa4NKmSzWkSQ846dT/6Xs9aUaNYNRsIbBWe4WGLCiGP7vZ
+TEzKgHGgMc1+DIOkpVHhrB88L2O/XZWNocd4jXN5Yi/m1dqw1JaMSRKkk/07Iq7
OjFeUtREr3lHqpCxA7JNNh0/u+687pXA
-----END ENCRYPTED PRIVATE KEY-----`

/*
Example:
```-----[REPLACE THIS] BEGIN RSA PRIVATE KEY-----
MIIE...
...
...AQAB
-----[REPLACE THIS] END RSA PRIVATE KEY-----```
*/

app.post("/", async (req, res) => {
  if (!PRIVATE_KEY) {
    throw new Error(
      'Private key is empty. Please check your env variable "PRIVATE_KEY".'
    );
  }

  if(!isRequestSignatureValid(req)) {
    // Return status code 432 if request signature does not match.
    // To learn more about return error codes visit: https://developers.facebook.com/docs/whatsapp/flows/reference/error-codes#endpoint_error_codes
    return res.status(432).send();
  }

  let decryptedRequest = null;
  try {
    decryptedRequest = decryptRequest(req.body, PRIVATE_KEY, PASSPHRASE);
  } catch (err) {
    console.error(err);
    if (err instanceof FlowEndpointException) {
      return res.status(err.statusCode).send();
    }
    return res.status(500).send();
  }

  const { aesKeyBuffer, initialVectorBuffer, decryptedBody } = decryptedRequest;
  console.log("💬 Decrypted Request:", decryptedBody);

  // TODO: Uncomment this block and add your flow token validation logic.
  // If the flow token becomes invalid, return HTTP code 427 to disable the flow and show the message in `error_msg` to the user
  // Refer to the docs for details https://developers.facebook.com/docs/whatsapp/flows/reference/error-codes#endpoint_error_codes

  /*
  if (!isValidFlowToken(decryptedBody.flow_token)) {
    const error_response = {
      error_msg: `The message is no longer available`,
    };
    return res
      .status(427)
      .send(
        encryptResponse(error_response, aesKeyBuffer, initialVectorBuffer)
      );
  }
  */

  const screenResponse = await getNextScreen(decryptedBody);
  console.log("👉 Response to Encrypt:", screenResponse);

  res.send(encryptResponse(screenResponse, aesKeyBuffer, initialVectorBuffer));
});

app.get("/", (req, res) => {
  res.send(`<pre>Nothing to see here.
Checkout README.md to start.</pre>`);
});

app.listen(PORT, () => {
  console.log(`Server is listening on port: ${PORT}`);
});

function isRequestSignatureValid(req) {
if (!APP_SECRET) {
    console.warn("App Secret is not set. Please add it in the .env file.");
    return true;
  }

  const signatureHeader = req.get("x-hub-signature-256");
  if (!signatureHeader) {
    console.error("Missing x-hub-signature-256 header");
    return false;
  }

  const signatureBuffer = Buffer.from(signatureHeader.replace("sha256=", ""), "hex");

  if (!req.rawBody) {
    console.error("Error: req.rawBody is undefined. Ensure middleware is set up correctly.");
    return false;
  }

  const hmac = crypto.createHmac("sha256", APP_SECRET);
  const digestString = hmac.update(req.rawBody).digest("hex");
  const digestBuffer = Buffer.from(digestString, "hex");

  if (!crypto.timingSafeEqual(digestBuffer, signatureBuffer)) {
    console.error("Error: Request Signature did not match");
    return false;
  }

  return true;
}
