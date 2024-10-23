/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2023 WireGuard LLC. All Rights Reserved.
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

typedef void(*logger_fn_t)(void *context, int level, const char *msg);
extern void wgSetLogger(void *context, logger_fn_t logger_fn);
extern int wgTurnOnIAN(const char *settings, int32_t tun_fd, const char *private_ip, const char *maybeNotMachines, uint32_t maybeNotMaxEvents, uint32_t maybeNotMaxActions);
extern int wgTurnOn(const char *settings, int32_t tun_fd, const char *maybeNotMachines, uint32_t maybeNotMaxEvents, uint32_t maybeNotMaxActions);
extern int wgTurnOnMultihop(const char *exitSettings, const char *entrySettings, const char *privateIp, int32_t tun_fd, const char *maybenotMachines, uint32_t maybeNotMaxEvents, uint32_t maybeNotMaxActons);
extern void wgTurnOff(int handle);
extern int64_t wgSetConfig(int handle, const char *exitSettings, const char *entrySettings);
extern char *wgGetConfig(int handle);
extern void wgBumpSockets(int handle);
extern void wgDisableSomeRoamingForBrokenMobileSemantics(int handle);
extern int wgOpenInTunnelICMP(int tunnelHandle, const char *address);
extern int wgCloseInTunnelICMP(int tunnelHandle, int socketHandle);
extern int32_t wgSendInTunnelPing(int tunnelHandle, int socketHandle, uint16_t pingId, int pingSize, uint16_t sequenceNumber);
extern int32_t wgRecvInTunnelPing(int tunnelHandle, int socketHandle);
extern int32_t wgOpenInTunnelTCP(int32_t tunnelHandle, const char *address);
extern int32_t wgCloseInTunnelTCP(int32_t tunnelHandle, int32_t socketHandle);
extern int32_t wgRecvInTunnelTCP(int32_t tunnelHandle, int32_t socketHandle, const char *data, int len);
extern int32_t wgSendInTunnelTCP(int32_t tunnelHandle, int32_t socketHandle, const char *data, int len);
extern const char *wgVersion();

#endif
