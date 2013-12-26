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
 * @brief NET Driver
 */

 #ifdef HAVE_CONFIG_H
#  include "config.h"
#endif // HAVE_CONFIG_H

#include "net.h"

#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/socket.h> /* basic socket definitions */
#include <sys/un.h> /* for Unix domain sockets */
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>

#include <nfc/nfc.h>
#include "nfc-internal.h"

#define LOG_GROUP    NFC_LOG_GROUP_COM
#define LOG_CATEGORY "libnfc.bus.net"

struct net_port_unix {
  int sock;
};

#define NET_DATA( X ) ((struct net_port_unix *) X)

static void 
net_error(const net_port np)
{
  (void)np;
}

net_port
net_open(const char *serverIP, const char *serverPortNum)
{
  struct net_port_unix *np = malloc(sizeof(struct net_port_unix));
  if(np == NULL){
  	log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "malloc");
  	return INVALID_NET_PORT;
  }

  np->sock = socket(PF_INET, SOCK_STREAM, 0);
  if ( np->sock <= 0 ){
  	//log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "Create Socket Failed::%lu", GetLastError());
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
  if ( ret < 0 )
  {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR, "Connect Server Error");
    net_error(np);
    return INVALID_NET_PORT;
  }

  log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_INFO, "Connected!");

  /** wait server to prepare. */
  //sleep(100);
  
  return np;
}


void
net_close(const net_port np)
{
  struct net_port_unix *npw;

  npw = (struct net_port_unix *)np;
  if(npw == INVALID_NET_PORT){
    return;
  }

  close(npw->sock);

  free(np);
}

#define NET_FLUSH_BUFFER_LEN      (1024)
void
net_flush_input(const net_port np, bool wait)
{
  // Check handler
  struct net_port_unix *npw;
  npw = (struct net_port_unix *)np;
  if(npw == INVALID_NET_PORT){
    return;
  }

  if(wait){
    sleep(50);
  }

  int res;
  unsigned long bytes_available = 0;
  res = ioctl(npw->sock,FIONREAD,&bytes_available);
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
}

int
net_receive(net_port np, uint8_t *pbtRx, const size_t szRx, void *abort_p, int timeout)
{
  int iAbortFd = abort_p ? *((int *)abort_p) : 0;
  int received_bytes_count = 0;
  int available_bytes_count = 0;
  const int expected_bytes_count = (int)szRx;
  int res;
  fd_set rfds;
  do {
select:
    // Reset file descriptor
    FD_ZERO(&rfds);
    FD_SET(NET_DATA(np)->sock, &rfds);

    if (iAbortFd) {
      FD_SET(iAbortFd, &rfds);
    }

    struct timeval timeout_tv;
    if (timeout > 0) {
      timeout_tv.tv_sec = (timeout / 1000);
      timeout_tv.tv_usec = ((timeout % 1000) * 1000);
    }

    res = select(MAX(NET_DATA(np)->sock, iAbortFd) + 1, &rfds, NULL, NULL, timeout ? &timeout_tv : NULL);

    if ((res < 0) && (EINTR == errno)) {
      // The system call was interupted by a signal and a signal handler was
      // run.  Restart the interupted system call.
      goto select;
    }

    // Read error
    if (res < 0) {
      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG, "Error: %s", strerror(errno));
      return NFC_EIO;
    }
    // Read time-out
    if (res == 0) {
      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG, "%s", "Timeout!");
      return NFC_ETIMEOUT;
    }

    if (FD_ISSET(iAbortFd, &rfds)) {
      // Abort requested
      log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_DEBUG, "%s", "Abort!");
      close(iAbortFd);
      return NFC_EOPABORTED;
    }

    // Retrieve the count of the incoming bytes
    res = ioctl(NET_DATA(np)->sock, FIONREAD, &available_bytes_count);
    if (res != 0) {
      return NFC_EIO;
    }
    // There is something available, read the data
    res = recv(NET_DATA(np)->sock, pbtRx + received_bytes_count, MIN(available_bytes_count, (expected_bytes_count - received_bytes_count)), 0);
    // Stop if the OS has some troubles reading the data
    if (res <= 0) {
      return NFC_EIO;
    }
    received_bytes_count += res;

  } while (expected_bytes_count > received_bytes_count);
  LOG_HEX(LOG_GROUP, "RX", pbtRx, szRx);
  return NFC_SUCCESS;
}


int
net_send(net_port np, const uint8_t *pbtTx, const size_t szTx, int timeout)
{
  int iResult;

  struct net_port_unix *npw;

  npw = (struct net_port_unix *)np;
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
  if (iResult < 0) {
    log_put(LOG_GROUP, LOG_CATEGORY, NFC_LOG_PRIORITY_ERROR,"Send failed.\n");
    net_error(np);
    return NFC_EIO;
  }
  LOG_HEX(LOG_GROUP, "TX", pbtTx, szTx);
  return 0;
}
