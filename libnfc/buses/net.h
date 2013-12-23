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
 * @brief NET Driver Header
 */

#ifndef __NFC_BUS_NET_H__
#  define __NFC_BUS_NET_H__

#  include <sys/time.h>

#  include <stdio.h>
#  include <string.h>
#  include <stdlib.h>

#  include <nfc/nfc-types.h>

// Define shortcut to types to make code more readable
typedef void *net_port;
#  define INVALID_NET_PORT (void*)(~1)

net_port net_open(const char *serverIP, const char *serverPortNum);
void    net_close(const net_port np);
void    net_flush_input(const net_port np, bool wait);
int     net_receive(net_port np, uint8_t *pbtRx, const size_t szRx, void *abort_p, int timeout);
int     net_send(net_port np, const uint8_t *pbtTx, const size_t szTx, int timeout);

#endif // __NFC_BUS_NET_H__
