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
MIIFJDBWBgkqhkiG9w0BBQ0wSTAxBgkqhkiG9w0BBQwwJAQQd6lQS6B5yB3w35l9
nsF+QAICCAAwDAYIKoZIhvcNAgkFADAUBggqhkiG9w0DBwQIzrJNJZQ76F4EggTI
TucgxOwQlFeqJIv8PNepQOToYpWZyYR6w8KOhc0T3N/9bI6dpLUSEuW5FbcM5zmx
33CsMfEqWuEnaALuhxWJfFWEQEYHyJMXgaFvW9k6W14ZmyTaW3S3rwKThsYWaZcc
PLx/stu0eaRDde8sBIi6tN8ujPJofpFFC7vo4mKNN46lE+CPwPNTeu/sRogdOv74
KS9LFxYt44bEooa4A2WCKd5EzyefN6eLx1j5Rpz9mcHBRBvwGEy211HduxqPXamc
GxqVdgUMz3a+MXCqhqBs4abhUw5jPhSwsxli+xNIAti7g4dgfTyuzI9v+PR6pnOL
xJrFbkpd0mvpvTwhufVB0k8zbJwDjDnb8DlTf75PAApRCJx6sUw7BlJEy43DHtzr
xMVWdd6qiMAroV50W/HHXMW649VbqWQPwdcoxE4OJykMIDZ+2orXrfh/PoVBvQoE
IBfBgWyuaBxAF/+2filulkpLwMHjEuxb8wssCA8gNnDNsHrlVMlFtdobUxHHE8ID
efviJVG/TXp4jcr8McF0mZBbP1FGKb2kuDhcBTGhBQgjJA7Xba0macAfXnmrJuGl
tPQshid4tO1GFuKkx0dWbTwlmcWgg4a3V++2+om2dRQ//NeyOEgG8/3hXArx699g
Jufjg8v7lQcMyYYwxEPxfNYjnuU5DeJn+ebgVP9vQvY+mLIA0arIj2RUhLBZgWZi
lHvlqI2ofXWpkJpuKqBYjOH7Vo6hkDQjo6h4uaS0YouuY7+di7UxE8zt0f/ODLWn
lYIqCJ9tvFPXkTJ9H9z3K8cA2QLgiZcvJTkHBMq5sKslsBb+iMiTwub+ka6Q0TM5
0EhJE4qQHMJKDtsrr0Qy6kXA7NlK3sLWMcFeNSmBUEW+K7GruvwZwAzWd3GVqjwo
XYvxjRFu82Yp5Ric1Q2/+VNK27gYD/ONcfpqrsvZo6G6bAVQ1vhLcqBdDDslyEbP
ix08SunoGCNzIGLpJ5j/0bDaz1RIfMvRwwtiNldhRHEv+q44AU9Hr5TdzGCNO9Sf
xMgUArYdObqAAwTUhlcM9Py0ZLl0Xvvh3lMjGUnXHvykBi8gNvcm1BZkQZTANXFJ
GG35B3+Q2oRtePTQxT1cgV4XOfM4NexOa3RPKbt4qnqcyCgYVtZa0nQW3JNMbbox
t9kP+8N7IjZMnxDwEG9WSc44GzCGK8kY3G/yxePnPCd8DVP6O2W1+uzka0mjsGj5
93U4wqEC3YwAjuuJXeX7pDe4ehyh1wF3aer4sSZbJMRnuPDWqMyscHjRqx+8K9ZR
2Abm/Uo8fjO3lKWTsvUfrf6brpxwlysHli6hq+i7oWIs5LRxwAIrsy8sx5gLTNrB
/sBz7xBXHXUoQ17LC/EPCyCuNDdCCTAy2zCSTzypKQxRVMRDldyC8xMOmc4GWYrq
8yu1uEYpD3HHA7eQXm+pwcwkaU9lgI5XyUhRuyuFucDpuyIzjuJCGLZsPw3XK8B/
iUoHbXrTPt42+OKdwMggVpsp1Ll03ogh69h0iE7zDxz9O9SzNEMFqunNj+G09ISx
Q0IKi7TQUwfWzilTUSEpaUXBpSL+C9RiOIrnd0h89kbzDEqU2PE6l4GuRrtvIuLK
k3aT53ltPKzgI5Aa/w2fVTCPoDW9kI2R
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
