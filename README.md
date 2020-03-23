[![](https://travis-ci.com/helium/lorawan-sniffer.svg?token=35YrBmyVB8LNrXzjrRop&branch=master)](https://travis-ci.com/helium/lorawan-sniffer)

# lorawan-sniffer

Download a compiled release [here](https://github.com/helium/lorawan-sniffer/releases).

## Features

LoRaWAN Sniffer is a utility which allows you to sniff and parse as LoRaWAN the UDP traffic to and from any packet forwarder that uses the Semtech UDP protocol.

If you load device information into the utility, session keys are derived during Over-the-Air-Authentication (OTAA) and data frames will be decrypted. Currently, ABP is not supported.

## Usage

The utility may be deployed in two ways:
* if a host exists which mirrors all UDP packets (such as the Helium Miner), the utility can do a simple connection to this host
* the utility can act as a passthrough; connect the packet forwarder to this utility (`0.0.0.0:1680`) and in turn, connect this utility to some host

Either way, starting up the utility is identical:

```
lorawan-sniffer -h 192.168.1.55:1681
```

If you want to use passthrough mode, you will need to connect your packet forward to the utility. For the Semtech packet foward, that means making changes to `global_conf.json`.

## Helium Image Quickstart

If you are using a production or development image of a Helium hotspot, you can use the `snipper_setup.sh` script to do two things:
* change the packet forwader's sub-band to 3 (905.5-906.9 MHz, Ch 16-23); this helps ensure that only this hotspot will talk to your LoRaWAN device (note: you will need to configure your LoRaWAN device exclusively for sub-band 3)
* enable mirroring on the Helium Miner; the Miner will now forward a copy to all UDP traffic to port 1681 of the Hotspot IP

```
sniffer_setup.sh <HotspotIP> [<HotspotPW>]
```

HotspotPW defaults to `hotspot`, the password of the development image. If you are using a production image, you will need to input the production image password.

## Loading Devices

Devices and their credentials may be loaded in two ways: 
* by using a local file
* by loading the devices from Helium Console (requires API key)

To load devices by file, simply create a local file called `lorawan-devices.json` and provide a JSON array of devices:
```
[
    {
        "app_eui": "5F3BD74E6778AB9B",
        "app_key": "EDC1A29400517C5312CFBFD5F56F69C2",
        "dev_eui": "3B595A22646AA4D5"
    }
]
```

To load devices from Console, use the console option:
```
lorawan-sniffer -h 192.168.1.55:1681 --console
```

If `.helium-console-config.toml` does not yet exist, you will be prompted for an API key and the file will be created, similar to when using the [Helium Console CLI](https://github.com/helium/helium-console-cli). Note that this file stores your API key in plain-text so only do this on trusted hosts.


## Example Session

Once everything is setup, you'll see output similar to this:

```
JoinRequest 906.3 MHz   SF10BW125   RSSI: -69   LSNR: 11.8
    AppEui: 5F3BD74E6778AB9B DevEui: 3B595B22646AA4D5 DevNonce: 7995
JoinAccept  925.7 MHz   SF10BW500
    AppNonce: E79DE9 NetId: 326548 DevAddr: 4ED73B5F
    DL Settings: DLSettings(0) RxDelay: 0
    Newskey: AES128([5F, 66, BE, 9A, 4, 29, 9E, 12, 58, 5E, F4, 13, F1, B7, 3, A0])
    Appskey: AES128([F1, 9E, B3, C, EC, 3E, BA, 81, B0, BF, EC, BB, 1E, 97, A0, 20])
UnconfirmedDataUp   905.5 MHz   SF10BW125   RSSI: -69   LSNR: 11.5
    DevAddr: 4ED73B5F, FCtrl(80, true), FCnt(0), FPort(1), 
    Decrypted(Data([de, ad, be, ef, 1]))
UnconfirmedDataDown 923.3 MHz   SF10BW500
    DevAddr: 4ED73B5F, FCtrl(a, true), FCnt(0)
    [LinkADRAns(LinkADRAnsPayload([0]))]
UnconfirmedDataUp   906.3 MHz   SF10BW125   RSSI: -69   LSNR: 11.8
    DevAddr: 4ED73B5F, FCtrl(84, true), FCnt(1)
    [LinkADRAns(LinkADRAnsPayload([6])), LinkADRAns(LinkADRAnsPayload([6]))]
UnconfirmedDataUp   906.7 MHz   SF10BW125   RSSI: -66   LSNR: 10.2
    DevAddr: 4ED73B5F, FCtrl(80, true), FCnt(2), FPort(1), 
    Decrypted(Data([de, ad, be, ef, 2]))
UnconfirmedDataUp   906.9 MHz   SF10BW125   RSSI: -69   LSNR: 11.2
    DevAddr: 4ED73B5F, FCtrl(80, true), FCnt(3), FPort(1), 
    Decrypted(Data([de, ad, be, ef, 3]))
```
