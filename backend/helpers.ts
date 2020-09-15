import dotenv from "dotenv";
import { set } from "lodash";
import { Request, Response, NextFunction } from "express";
import { validationResult } from "express-validator";
// @ts-ignore
import OktaJwtVerifier from "@okta/jwt-verifier";

dotenv.config({ path: ".env.local" });
dotenv.config();

// Okta Validate the JWT Signature

const oktaJwtVerifier = new OktaJwtVerifier({
  issuer: `https://${process.env.REACT_APP_OKTA_DOMAIN}/oauth2/default`,
  clientId: process.env.REACT_APP_OKTA_CLIENTID,
  assertClaims: {
    aud: "api://default",
    cid: process.env.REACT_APP_OKTA_CLIENTID,
  },
});

const verifyOktaToken = (req: Request, res: Response, next: NextFunction) => {
  const bearerHeader = req.headers["authorization"];
  console.log("req", req.headers);
  console.log("authorization", bearerHeader);

  if (bearerHeader) {
    const bearer = bearerHeader.split(" ");
    const bearerToken = bearer[1];

    oktaJwtVerifier
      .verifyAccessToken(bearerToken)
      .then((jwt: any) => {
        // the token is valid
        console.log(jwt.claims);
        return next();
      })
      .catch((err: any) => {
        // a validation failed, inspect the error
        console.log("error", err);
      });
  }
  res.status(401).send({
    error: "Unauthorized",
  });
};

export const checkJwt = verifyOktaToken; //.unless({ path: ["/testData/*"] });

export const ensureAuthenticated = (req: Request, res: Response, next: NextFunction) => {
  if (req.isAuthenticated()) {
    // @ts-ignore
    // Map sub to id on req.user
    if (req.user?.sub) {
      // @ts-ignore
      set(req.user, "id", req.user.sub);
    }
    return next();
  }
  /* istanbul ignore next */
  res.status(401).send({
    error: "Unauthorized",
  });
};

export const validateMiddleware = (validations: any[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    await Promise.all(validations.map((validation: any) => validation.run(req)));

    const errors = validationResult(req);
    if (errors.isEmpty()) {
      return next();
    }

    res.status(422).json({ errors: errors.array() });
  };
};
