/*
 * Copyright (C) 2026 Tobias Brunner
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * Provides an EAP method implementation that does no real work.
 *
 * @defgroup mock_eap mock_eap
 * @{ @ingroup test_utils_c
 */

#ifndef MOCK_EAP_H_
#define MOCK_EAP_H_

#include <sa/eap/eap_method.h>

/**
 * Creates an EAP method acting as server.
 *
 * @param server	ID of the EAP server
 * @param peer		ID of the EAP client
 * @return			created object
 */
eap_method_t *mock_eap_create_server(identification_t *server,
									 identification_t *peer);

/**
 * Creates an EAP method acting as client.
 *
 * @param server	ID of the EAP server
 * @param peer		ID of the EAP client
 * @return			created object
 */
eap_method_t *mock_eap_create_peer(identification_t *server,
								   identification_t *peer);

#endif /** MOCK_EAP_H_ @}*/
