# PecuniatorDotGo
##### An Open Source API and client suite for PSD2 compliant banks and their X2SA APIs

- - - -

## How to try it out
1. Grab prebuilt binary from the [releases page](https://github.com/Merzlabs/pecuniatordotgo/releases/tag/webflow)
2. Place it in the folder where your secrets folder resides
    * (Optional on Linux) run `chmod +x ./pecuniatordotgo` to give executable permissions
3. Run the binary by typing `./pecuniatordotgo -cert secrets/<path_to>/certificate.pem -key secrets/<path_to>/priv.key`
4. Open `http://127.0.0.1:8080/index` in your browser and enter the login data
5. Test balances endpoint by opening `http://127.0.0.1:8080/accounts`
