# vayne

#### Variables

- `VAYNE_DNS` DNS of the web project `example.com`
- `VAYNE_PORT` Port of the HTTPS service `443`
- `VAYNE_ROOT` Directory of the root web project `C\www`
- `VAYNE_CERT` The certificate of the vayne project `C:\Certbot\live\example.com\cert.pem`
- `VAYNE_KEY` The key of the vayne project `C:\Certbot\live\example.com\privkey.pem`
- `VAYNE_CHAIN` The chain of the vayne project `C:\Certbot\live\example.com\chain.pem`

#### Security

- Strict-Transport-Security
- Content-Security-Policy limited to self
- External iframe disabled
- Mime-sniffing disabled
- XSS protection activated
- Permissions-Policy limited to geolocation and fullscreen
- Referrer-Policy set to no-referrer
