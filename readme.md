
# JSRP Javascript Secure Remote Password (SRP) Demo

This is a demo application of how to register and authenticate a user with the JSRP Secure Remote Password (SRP SRP6a) library [`jsrp`](https://github.com/alax/jsrp.git).

To get the code either clone the [repo](https://github.com/raqqun/jsrp-demo.git)

To run it:

```sh
npm start
```

Then open a browser at http://localhost:8080/

When you authenticate (after you have registered) both the browser and the server will `console.log` a line such as:

```
shared key: aa8942427a348b8ed3386df47458feb2b2eef9a9fe9e121d2a41fa2d60994750
```

That log line is the strong session key `K` as described on the [SRP design page](http://srp.stanford.edu/design.html). This can be used for follow on cryptography such as HMAC signing of JWT web tokens using HS256.
