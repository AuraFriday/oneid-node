# oneid-node

Node.js SDK for [1id.com](https://1id.com) -- hardware-anchored identity for AI agents.

> **Status: Planned.** The Node.js SDK is not yet implemented.
> See [oneid-sdk](https://github.com/AuraFriday/oneid-sdk) for the Python SDK,
> which is fully functional today.

## Planned API

The Node.js SDK will mirror the Python SDK API:

```javascript
import { OneID } from '@1id/sdk';

const identity = await OneID.enroll({ requestTier: 'declared' });
console.log(`Enrolled: ${identity.handle}`);

const token = await OneID.getToken();
// Use token.accessToken for API calls
```

## License

MIT
