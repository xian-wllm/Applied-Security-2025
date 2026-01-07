# iMoves CA

## Running the iMoves CA

```bash
cd lab
./start.sh
```

- Access the Client at http://localhost:6080 (password: money4band)
- Access the Portal UI at https://portal.imovies.lan inside the Client Browser
- Test issuing EMPLOYEE or CA_ADMIN certificates with user: `ps`, password: `KramBamBuli`
- After getting a CA_ADMIN certificate and installing it in the browser, access https://portal.imovies.lan/admin/dashboard
- With the preinstalled ms.imovies.lan SYS_ADMIN certificate, access Guacamole at https://guac.imovies.lan/guacamole and click on connect with certificate/smartcard
- Wazuh Manager UI at https://kibana.imovies.lan (username: `kibanaserver`, password: `kibanaserver`) for SOC_ANALYST

Stop the lab with:

```bash
./stop.sh
```
