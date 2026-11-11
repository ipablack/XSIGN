import os
import secrets

import uvicorn

from xsignbot.core import store


if __name__ == "__main__":
    if not os.environ.get("HMAC_SECRET"):
        secret = store().update(
            "state/hmac-secret.json",
            dict,
            lambda state: state.setdefault("value", secrets.token_urlsafe(32)),
        )
        os.environ["HMAC_SECRET"] = secret
    os.environ.setdefault("XSIGN_REGISTER_WEBHOOK", "1")
    port = int(os.environ.get("PORT") or os.environ.get("SERVER_PORT") or 8080)
    uvicorn.run("api.index:app", host="0.0.0.0", port=port, access_log=False)
