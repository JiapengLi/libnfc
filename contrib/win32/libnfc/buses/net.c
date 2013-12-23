/*-
 * Free/Libre Near Field Communication (NFC) library
 *
 * Libnfc historical contributors:
 * Copyright (C) 2009      Roel Verdult
 * Copyright (C) 2009-2013 Romuald Conty
 * Copyright (C) 2010-2012 Romain Tartière
 * Copyright (C) 2010-2013 Philippe Teuwen
 * Copyright (C) 2012-2013 Ludovic Rousseau
 * Copyright (C) 2013      Jiapeng Li
 * See AUTHORS file for a more comprehensive list of contributors.
 * Additional contributors of this file:
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

/**
 * @file net.c
 * @brief Windows NET Driver
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif // HAVE_CONFIG_H

#include "net.h"

#include <nfc/nfc.h>
#include "nfc-internal.h"

#include <inttypes.h>
#include "log.h"

#define LOG_GROUP    NFC_LOG_GROUP_COM
#define LOG_CATEGORY "libnfc.bus.net_win32"

// Handle platform specific includes
#include "contrib/windows.h"
#define delay_ms( X ) Sleep( X )

struct net_port_windows {
  SOCKET sock;
};

static void 
net_error(const net_port np)
{
  // struct net_port_windows *npw;

  // npw = (struct net_port_windows *)np;
  // if(npw == INVALID_NET_PORT){
  //   return;
  // }
  log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "Error Code: %d", WSAGetLastError());
  // closesocket(npw->sock);
  // WSACleanup();
}

net_port
net_open(const char *serverIP, const char *serverPortNum)
{
  WSADATA wsaData;
  int iResult;

  struct net_port_windows *np = malloc(sizeof(struct net_port_windows));
  if(np == NULL){
  	log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "malloc");
  	return INVALID_NET_PORT;
  }

  // Initialize Winsock
  iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
  if (iResult != 0) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "WSAStartup failed: %d", iResult);
    return INVALID_NET_PORT;
  }

  np->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if ( np->sock == INVALID_SOCKET ){
  	log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "Create Socket Failed::%lu", GetLastError());
    return INVALID_NET_PORT;
  }

  struct sockaddr_in ServerAddr;
  int portNum = atoi(serverPortNum);

  if(portNum == 0){
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "Port Number Invalid.");
    return INVALID_NET_PORT;
  }

  ServerAddr.sin_family = AF_INET;
  ServerAddr.sin_addr.s_addr = inet_addr(serverIP);
  ServerAddr.sin_port = htons(portNum);
  memset(ServerAddr.sin_zero, 0x00, 8);

  int ret = connect(np->sock,(struct sockaddr*)&ServerAddr, sizeof(ServerAddr));
  if ( ret == SOCKET_ERROR )
  {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "Connect Server Error");
    net_error(np);
    return INVALID_NET_PORT;
  }

  log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_INFO, "Connected!");

  /** wait server to prepare. */
  Sleep(100);
  
  return np;
}


void
net_close(const net_port np)
{
  struct net_port_windows *npw;

  npw = (struct net_port_windows *)np;
  if(npw == INVALID_NET_PORT){
    return;
  }

  closesocket(npw->sock);
  WSACleanup();

  free(np);
}

#define NET_FLUSH_BUFFER_LEN      (1024)
void
net_flush_input(const net_port np, bool wait)
{
#if 1
  // Check handler
  struct net_port_windows *npw;
  npw = (struct net_port_windows *)np;
  if(npw == INVALID_NET_PORT){
    return;
  }

  if(wait){
    Sleep(50);
  }

  int res;
  unsigned long bytes_available = 0;
  res = ioctlsocket(npw->sock,FIONREAD,&bytes_available);
  if (res != 0) {
    return;
  }

  if(bytes_available == 0){
    return;
  }

  char *buf = malloc(bytes_available);
  if(buf == NULL ){
    return;
  }

  res = recv(npw->sock, buf, bytes_available, 0);
  if(res < 0){
    perror("net flush input.");
    free(buf);
    return;
  }
  log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG, "%lu bytes flushed.", bytes_available);

  free(buf);
#else
  // Check handler
  struct net_port_windows *npw;
  npw = (struct net_port_windows *)np;
  if(npw == INVALID_NET_PORT){
    return;
  }

  unsigned long bytes_available=5;
  ioctlsocket(npw->sock,FIONREAD,&bytes_available);
  if(bytes_available == 0){
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "No data need to be cleared.");
  }

  // check if socket is readble
  int timeout, res;
  fd_set rfds;
  
  FD_ZERO(&rfds);
  FD_SET (npw->sock, &rfds);
  
  if(wait==true){
    timeout = 50;  
  }else{
    /**  */
    timeout = 1;
  }

  struct timeval timeouts;
  timeouts.tv_sec = timeout/1000;
  timeouts.tv_usec = (timeout%1000)*1000;

  res = select(npw->sock+1, &rfds, NULL, NULL, timeout ? &timeouts : NULL);
  if(res < 0){
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "select failed.");
    return ;
  }else if(res == 0){
    return ;
  }

  log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_INFO, "flush timeout %ums", timeout);

  if (setsockopt (npw->sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(DWORD)) < 0){
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "setsockopt failed.");
    net_error(np);
    return;
  }
  

  int ret;
  do{
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_INFO, "net driver clear recv buffer.");
    ret = recv(npw->sock, buf, NET_FLUSH_BUFFER_LEN, 0);
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_INFO, "%d bytes cleared.", ret);
  }while(ret == NET_FLUSH_BUFFER_LEN);

  free(buf);
#endif
}

int
net_receive(net_port np, uint8_t *pbtRx, const size_t szRx, void *abort_p, int timeout)
{
  DWORD dwBytesToGet = (DWORD)szRx;
  DWORD dwBytesReceived = 0;
  DWORD dwTotalBytesReceived = 0;
  struct net_port_windows *npw;

  npw = (struct net_port_windows *)np;
  if(npw == INVALID_NET_PORT){
    return NFC_EIO;
  }

  struct timeval timeouts;
  timeouts.tv_sec = timeout/1000;
  timeouts.tv_usec = (timeout%1000)*1000;

  fd_set rfds;
  int res;

  FD_ZERO(&rfds);
  FD_SET (npw->sock, &rfds);

  res = select(npw->sock+1, &rfds, NULL, NULL, timeout ? &timeouts : NULL);
  if(res < 0){
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "select failed.");
    return NFC_EIO;
  }else if(res == 0){
    return NFC_EIO;
  }

  unsigned long bytes_available = 0;
  res = ioctlsocket(npw->sock,FIONREAD,&bytes_available);
  if (res != 0) {
    return NFC_EIO;
  }

  if(bytes_available == 0){
    return NFC_EIO;
  }

  if (setsockopt (npw->sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeouts, sizeof(timeouts)) < 0){
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "setsockopt failed.\n");
    net_error(np);
    return NFC_EIO;
  }
  log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG, "Timeouts are set to %u ms", timeout);

  // TODO Enhance the reception method
  // - According to MSDN, it could be better to implement nfc_abort_command() mecanism using Cancello()
  volatile bool *abort_flag_p = (volatile bool *)abort_p;
  do {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG, "Socket recv");
    res = recv(npw->sock, (char *)pbtRx + dwTotalBytesReceived, dwBytesToGet, 0);

    if (res < 0) {
      DWORD err = GetLastError();
      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "ReadFile error: %lu", err);
      return NFC_EIO;
    } else if (res == 0) {
      return NFC_ETIMEOUT;
    }

    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG, "Receive %u bytes", res);
    dwBytesReceived = res;
    dwTotalBytesReceived += dwBytesReceived;

    if (((DWORD)szRx) > dwTotalBytesReceived) {
      dwBytesToGet -= dwBytesReceived;
    }

    if (abort_flag_p != NULL && (*abort_flag_p) && dwTotalBytesReceived == 0) {
      return NFC_EOPABORTED;
    }
  } while (((DWORD)szRx) > dwTotalBytesReceived);

  LOG_HEX(LOG_GROUP, "RX", pbtRx, szRx);

  return (dwTotalBytesReceived == (DWORD) szRx) ? 0 : NFC_EIO;
}


int
net_send(net_port np, const uint8_t *pbtTx, const size_t szTx, int timeout)
{
  int iResult;

  struct net_port_windows *npw;

  npw = (struct net_port_windows *)np;
  if(npw == INVALID_NET_PORT){
    return NFC_EIO;
  }

  struct timeval timeouts;      
  timeouts.tv_sec = timeout/1000;
  timeouts.tv_usec = (timeout%1000)*1000;

  if (setsockopt (npw->sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeouts,
    sizeof(timeouts)) < 0){
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "setsockopt failed.\n");
    net_error(np);
    return NFC_EIO;
  }

  // Send an initial buffer
  iResult = send(npw->sock, (const char *)pbtTx, szTx, 0);
  if (iResult == SOCKET_ERROR) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,"Send failed.\n");
    net_error(np);
    return NFC_EIO;
  }

  return 0;
}


