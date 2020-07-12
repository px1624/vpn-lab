# :trophy: VPN Lab
This is an implementation of the VPN Lab designed by the [SEEDLabs](https://seedsecuritylabs.org/). This VPN is implemented using TUN/TAP and it supports tunnel encryption (tls/ssl), server and client authentication (openssl), and multiple client connections (socket). The full lab instructions can be found [here](https://seedsecuritylabs.org/Labs_16.04/Networking/VPN/).

# :clipboard: Requirements

* make
* openssl
* TUN/TAP
* Linux VM (Tested on [SEEDLabs Ubuntu16.4](https://seedsecuritylabs.org/lab_env.html))

# :gear: Installation

```shell
> make
``` 

# :rocket: How to Run
To run the server:
```shell
> sudo ./vpnserver [server_cert] [server_key]
```

To run the client: 
```shell
> sudo ./vpnclient  [hostname] [port]
```

Note: You also need to configure the TUN interfaces on both sides
and set up routings. See the [lab description](https://seedsecuritylabs.org/Labs_16.04/Networking/VPN/) for instructions.

# :page_facing_up: License