/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2023 WireGuard LLC. All Rights Reserved.
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint32_t maybeNotMaxEvents;
    uint32_t maybeNotMaxActions;
    double maybeNotMaxPadding;
    double maybeNotMaxBlocking;
} DaitaGoParameters;

typedef struct {
	void* inner;
} WireGuardParameters;

extern uintptr_t wgParamsInit(const char *exitConfig, const char* privateIp4, const char *privateIp6);
extern int wgParamsSetEntry(uintptr_t params, const char *entryConfig);
extern int wgParamsSetUser(uintptr_t params, const char *userConfig, const char* userIp4, const char* userIp6);
extern int wgParamsSetDaita(uintptr_t params, DaitaGoParameters daitaGoParameters, const char* maybenotMachines);
extern void wgParamsDestroy(uintptr_t params);
extern void test_daita(DaitaGoParameters *context);
typedef void(*logger_fn_t)(void *context, int level, const char *msg);
extern void wgSetLogger(void *context, logger_fn_t logger_fn);
extern int wgTurnOn(uintptr_t params , int32_t tun_fd);
extern int wgTurnOnMultihop(WireGuardParameters params, int32_t tun_fd);
extern void wgTurnOff(int handle);
extern int64_t wgSetConfig(int handle, const char *exitSettings, const char *entrySettings);
extern char *wgGetConfig(int handle);
extern void wgBumpSockets(int handle);
extern void wgDisableSomeRoamingForBrokenMobileSemantics(int handle);
extern int wgOpenInTunnelICMP(int tunnelHandle, const char *address);
extern int wgCloseInTunnelICMP(int tunnelHandle, int socketHandle);
extern int32_t wgSendInTunnelPing(int32_t tunnelHandle, int32_t socketHandle, uint16_t pingId, int32_t pingSize, uint16_t sequenceNumber);
extern int32_t wgRecvInTunnelPing(int32_t tunnelHandle, int32_t socketHandle);
extern int32_t wgOpenInTunnelTCP(int32_t tunnelHandle, const char *address, uint64_t connectTimeout);
extern int32_t wgCloseInTunnelTCP(int32_t tunnelHandle, int32_t socketHandle);
extern int32_t wgRecvInTunnelTCP(int32_t tunnelHandle, int32_t socketHandle, uint8_t *data, int32_t len);
extern int32_t wgSendInTunnelTCP(int32_t tunnelHandle, int32_t socketHandle, const uint8_t *data, int32_t len);
extern const char *wgVersion();

#endif
